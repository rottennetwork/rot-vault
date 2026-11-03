#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import string
from decimal import Decimal
from pathlib import Path
from typing import Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from rich.cells import cell_len
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Vertical
    from textual.screen import ModalScreen, Screen
    from textual.theme import Theme
    from textual.widgets import DataTable, Footer, Input, Label, OptionList
    from textual.widgets.option_list import Option
except ImportError:
    raise SystemExit("Missing packages. Run: pip install textual cryptography")


# ---- small helpers ----

# the default look: black with purple accents
# change any color here, or press ctrl+p in the app to switch to another built-in theme
ROT_THEME = Theme(
    name="rotvault",
    primary="#8b5cf6",
    secondary="#6d28d9",
    accent="#a78bfa",
    foreground="#e9e3ff",
    background="#000000",
    surface="#0c0814",
    panel="#150f24",
    success="#34d399",
    warning="#fbbf24",
    error="#f87171",
    dark=True,
)

NEW_ID = "__new__"  # id of the '+ new table' row in the list
DEFAULT_COLUMNS = "Emails, Passwords, Application, 2AUTH"
# columns with these names get true/false values and the space key flips them
BOOL_COLUMNS = {"2auth", "2fa", "mfa", "totp", "otp"}


def looks_secret(name: str) -> bool:
    # hide columns that sound private, like password, token or pin
    words = re.findall(r"[a-z0-9]+", name.lower())
    return any(w.startswith(("pass", "secret", "token")) or w in ("pin", "cvv", "key") for w in words)


def looks_money(name: str) -> bool:
    # columns with price or cost in the name, or a $, count as money
    if "$" in name:
        return True
    words = re.findall(r"[a-z0-9]+", name.lower())
    return any(w.startswith(("pric", "cost")) for w in words)


def is_money(col: dict) -> bool:
    # a saved choice wins, older tables without one go by the name
    if "money" in col:
        return col["money"]
    return looks_money(col["name"])


def to_number(value: str) -> Optional[Decimal]:
    # pull the first number out of text like "$1,200" or "about 50"
    cleaned = re.sub(r"[$,\s]", "", value)
    found = re.search(r"-?\d+(?:\.\d+)?", cleaned)
    return Decimal(found.group()) if found else None


def money_text(total: Decimal, dollar: bool) -> str:
    # 1400 -> 1,400 and 12.5 -> 12.50, with a $ if the column used one
    text = f"{abs(total):,.2f}"
    if text.endswith(".00"):
        text = text[:-3]
    text = ("$" if dollar else "") + text
    return "-" + text if total < 0 else text


def is_bool_column(name: str) -> bool:
    return name.strip().lower() in BOOL_COLUMNS


def generate_password(length: int = 20) -> str:
    # keep trying until it has lower, upper, a number and a symbol
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%^&*-_" for c in pw)):
            return pw


# ---- vault: everything about encryption and files ----

class Vault:
    # one key (made from your master password) unlocks the index and every table

    def __init__(self, root: Path):
        self.root = Path(root).expanduser()
        self.salt_path = self.root / ".salt"
        self.key: Optional[bytes] = None
        self.index_path: Optional[Path] = None
        self.tables: dict[str, str] = {}  # random file name -> real table name

    def exists(self) -> bool:
        return self.salt_path.exists()

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        # scrypt is slow on purpose so password guessing is expensive
        return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode())

    # the index file name comes from the key, so it can't be guessed without it
    def _index_path_for(self, key: bytes) -> Path:
        return self.root / hmac.new(key, b"index", hashlib.sha256).hexdigest()[:32]

    @staticmethod
    # AES-256-GCM with a fresh random nonce saved at the front of the file
    def _encrypt(key: bytes, plain: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, plain, None)

    @staticmethod
    def _decrypt(key: bytes, blob: bytes) -> bytes:
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)

    def _write(self, path: Path, plain: bytes) -> None:
        # write to a temp file then swap it in, so a crash can't corrupt the real one
        tmp = path.with_name(secrets.token_hex(8) + ".tmp")
        tmp.write_bytes(self._encrypt(self.key, plain))
        os.replace(tmp, path)

    def unlock(self, password: str) -> bool:
        # first run makes a new vault, later runs just check the password
        # a wrong password fails because the index can't be decrypted
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        if not self.exists():
            salt = os.urandom(16)
            self.salt_path.write_bytes(salt)
            self.key = self._derive(password, salt)
            self.index_path = self._index_path_for(self.key)
            self.tables = {}
            self._save_index()
            return True
        key = self._derive(password, self.salt_path.read_bytes())
        path = self._index_path_for(key)
        if not path.exists():
            return False
        try:
            data = json.loads(self._decrypt(key, path.read_bytes()))
        except (InvalidTag, ValueError):
            return False
        self.key, self.index_path, self.tables = key, path, data["tables"]
        return True

    def _save_index(self) -> None:
        self._write(self.index_path, json.dumps({"tables": self.tables}).encode())

    def list_tables(self) -> list[tuple[str, str]]:
        return sorted(self.tables.items(), key=lambda kv: kv[1].lower())

    def create_table(self, name: str, columns: list[str]) -> str:
        fid = secrets.token_hex(16)
        self.tables[fid] = name
        self.save_table(fid, {
            "columns": [{"name": c, "secret": looks_secret(c)} for c in columns],
            "rows": [],
        })
        self._save_index()
        return fid

    def load_table(self, fid: str) -> dict:
        return json.loads(self._decrypt(self.key, (self.root / fid).read_bytes()))

    def save_table(self, fid: str, data: dict) -> None:
        self._write(self.root / fid, json.dumps(data).encode())

    def rename_table(self, fid: str, name: str) -> None:
        self.tables[fid] = name
        self._save_index()

    def delete_table(self, fid: str) -> None:
        (self.root / fid).unlink(missing_ok=True)
        self.tables.pop(fid, None)
        self._save_index()


# ---- popups: text box and yes/no ----

class InputModal(ModalScreen[Optional[str]]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+g", "generate", "Generate password", show=False),
    ]

    def __init__(self, heading: str, value: str = "", hint: str = "", generate: bool = False):
        super().__init__()
        self.heading, self.initial, self.hint, self.generate = heading, value, hint, generate

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.heading, classes="brand")
            yield Input(value=self.initial, id="field")
            hint = self.hint
            if self.generate:
                hint = (hint + "   " if hint else "") + "ctrl+g makes a strong password"
            yield Label(hint or "enter to save, esc to cancel", classes="sub")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_generate(self) -> None:
        if self.generate:
            field = self.query_one("#field", Input)
            field.value = generate_password()
            field.cursor_position = len(field.value)


class ConfirmModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "yes", "Yes"),
        Binding("n", "no", "No"),
        Binding("escape", "no", "No"),
    ]

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.message, classes="brand")
            yield Label("y to confirm, n or esc to cancel", classes="sub")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


# ---- screens: login, table list, table view ----

class LoginScreen(Screen[bool]):
    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self.is_new = not vault.exists()

    def compose(self) -> ComposeResult:
        with Vertical(id="card"):
            yield Label("rotvault", classes="brand")
            if self.is_new:
                yield Label("Create a master password. There is no recovery if you forget it.", classes="sub")
                yield Input(placeholder="master password (8+ characters)", password=True, id="pw")
                yield Input(placeholder="repeat it", password=True, id="pw2")
            else:
                yield Label("Unlock your vault", classes="sub")
                yield Input(placeholder="master password", password=True, id="pw")
            yield Label("", id="msg")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        pw = self.query_one("#pw", Input)
        msg = self.query_one("#msg", Label)
        if self.is_new:
            if event.input.id == "pw":
                self.query_one("#pw2", Input).focus()
                return
            if len(pw.value) < 8:
                msg.update("Use at least 8 characters")
                return
            if pw.value != self.query_one("#pw2", Input).value:
                msg.update("Those do not match")
                return
        if self.vault.unlock(pw.value):
            self.dismiss(True)
        else:
            msg.update("Wrong password")
            pw.value = ""
            pw.focus()


class HomeScreen(Screen):
    BINDINGS = [
        Binding("n", "new", "New table"),
        Binding("v", "view", "View only"),
        Binding("r", "rename", "Rename"),
        Binding("d", "delete", "Delete"),
        Binding("q", "quit_app", "Lock and quit"),
    ]

    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault

    def compose(self) -> ComposeResult:
        with Vertical(id="card"):
            yield Label("rotvault", classes="brand")
            yield Label("Pick a table. Enter edits, v opens it view only.", classes="sub")
            yield OptionList(id="tables")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_list()
        self.query_one("#tables", OptionList).focus()

    def refresh_list(self, select: Optional[str] = None) -> None:
        ol = self.query_one("#tables", OptionList)
        ol.clear_options()
        ids = []
        for fid, name in self.vault.list_tables():
            ol.add_option(Option(Text(name), id=fid))
            ids.append(fid)
        ol.add_option(Option(Text("+ New table", style="italic"), id=NEW_ID))
        if select in ids:
            ol.highlighted = ids.index(select)
        else:
            ol.highlighted = 0

    def current_id(self) -> Optional[str]:
        ol = self.query_one("#tables", OptionList)
        if ol.highlighted is None:
            return None
        fid = ol.get_option_at_index(ol.highlighted).id
        return None if fid == NEW_ID else fid

    def open_table(self, fid: str, readonly: bool = False) -> None:
        name = self.vault.tables[fid]
        self.app.push_screen(TableScreen(self.vault, fid, name, readonly))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id == NEW_ID:
            self.action_new()
        else:
            self.open_table(event.option.id)

    def action_view(self) -> None:
        fid = self.current_id()
        if fid:
            self.open_table(fid, readonly=True)

    def action_new(self) -> None:
        def got_name(name: Optional[str]) -> None:
            if not name or not name.strip():
                return
            name = name.strip()

            def got_cols(raw: Optional[str]) -> None:
                if raw is None:
                    return
                cols = [c.strip() for c in raw.split(",") if c.strip()]
                if not cols:
                    self.notify("A table needs at least one column", severity="warning")
                    return
                fid = self.vault.create_table(name, cols)
                self.refresh_list(fid)
                self.open_table(fid)

            self.app.push_screen(
                InputModal("Columns", DEFAULT_COLUMNS, hint="separate with commas, change them any time"),
                got_cols,
            )

        self.app.push_screen(InputModal("New table name"), got_name)

    def action_rename(self) -> None:
        fid = self.current_id()
        if not fid:
            return

        def done(name: Optional[str]) -> None:
            if name and name.strip():
                self.vault.rename_table(fid, name.strip())
                self.refresh_list(fid)

        self.app.push_screen(InputModal("Rename table", self.vault.tables[fid]), done)

    def action_delete(self) -> None:
        fid = self.current_id()
        if not fid:
            return

        def done(yes: Optional[bool]) -> None:
            if yes:
                self.vault.delete_table(fid)
                self.refresh_list()

        self.app.push_screen(ConfirmModal(f"Delete '{self.vault.tables[fid]}' for good?"), done)

    def action_quit_app(self) -> None:
        self.app.exit()


# these are blocked when a table is opened in view only mode
EDIT_ACTIONS = {"add_row", "del_row", "add_col", "del_col", "rename_col", "toggle_secret", "toggle_money", "flip", "edit"}


class TableScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("e", "edit", "Edit"),
        Binding("a", "add_row", "Add row"),
        Binding("d", "del_row", "Del row"),
        Binding("n", "add_col", "Add col"),
        Binding("x", "del_col", "Del col"),
        Binding("r", "rename_col", "Rename col"),
        Binding("t", "toggle_secret", "Hide col"),
        Binding("m", "toggle_money", "Money col"),
        Binding("s", "reveal", "Reveal"),
        Binding("c", "copy", "Copy"),
        Binding("ctrl+l", "redraw", "Redraw", show=False),
        Binding("space", "flip", "Flip true/false", show=False),
    ]

    def __init__(self, vault: Vault, fid: str, name: str, readonly: bool):
        super().__init__()
        self.vault, self.fid, self.table_name, self.readonly = vault, fid, name, readonly
        self.data = vault.load_table(fid)
        self.reveal = False

    # textual asks this before running a key action, returning False disables it
    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        if self.readonly and action in EDIT_ACTIONS:
            return False
        return True

    def compose(self) -> ComposeResult:
        with Vertical(id="grid"):
            yield DataTable(cursor_type="cell", zebra_stripes=False)
        yield Label("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        grid = self.query_one("#grid")
        grid.border_title = self.table_name
        grid.border_subtitle = "view only" if self.readonly else "editing"
        self.rebuild(0, 0)
        self.query_one(DataTable).focus()

    # -- drawing the table --

    def shown(self, col: int, value: str) -> Text:
        # show dots instead of the value for hidden columns
        if self.data["columns"][col]["secret"] and not self.reveal and value:
            return Text("\u2022" * min(len(value), 10))
        return Text(value)

    def rebuild(self, row: Optional[int] = None, col: Optional[int] = None) -> None:
        # redraw the whole table and put the cursor back where it was
        dt = self.query_one(DataTable)
        row = dt.cursor_row if row is None else row
        col = dt.cursor_column if col is None else col
        dt.clear(columns=True)
        shown_rows = [[self.shown(i, v) for i, v in enumerate(r)] for r in self.data["rows"]]
        totals = self.totals_cells()
        # set every column width ourselves from the content, textual's auto width
        # can go stale after edits and leave columns too wide or too narrow
        for i, c in enumerate(self.data["columns"]):
            cells = [c["name"]] + [r[i].plain for r in shown_rows] + ([totals[i].plain] if totals else [])
            dt.add_column(Text(c["name"]), width=max(cell_len(t) for t in cells), key=str(i))
        for cells in shown_rows:
            dt.add_row(*cells)
        if totals:
            dt.add_row(*totals)
        if self.data["rows"]:
            dt.move_cursor(
                row=max(0, min(row, len(self.data["rows"]) - 1)),
                column=max(0, min(col, len(self.data["columns"]) - 1)),
            )
        self.update_status()
        # repaint everything now and once more after layout settles, some terminals
        # (windows especially) can leave old text on screen after a partial update
        dt.refresh(layout=True)
        self.call_after_refresh(dt.refresh, layout=True)

    def totals(self) -> tuple[dict, dict]:
        # add up every money column, blank or non-number cells count as zero
        sums, dollars = {}, {}
        for i, col in enumerate(self.data["columns"]):
            if not is_money(col):
                continue
            sums[i] = Decimal(0)
            dollars[i] = False
            for row in self.data["rows"]:
                number = to_number(row[i])
                if number is not None:
                    sums[i] += number
                if "$" in row[i]:
                    dollars[i] = True
        return sums, dollars

    def totals_cells(self) -> Optional[list]:
        # the totals row is drawn on the fly and never saved with the table
        sums, dollars = self.totals()
        if not sums or not self.data["rows"]:
            return None
        grand = sum(sums.values(), Decimal(0))
        label = "total"
        if len(sums) > 1:
            label += ": " + money_text(grand, any(dollars.values()))
        cells, labeled = [], False
        for i in range(len(self.data["columns"])):
            if i in sums:
                cells.append(Text(money_text(sums[i], dollars[i]), style="bold"))
            elif not labeled:
                cells.append(Text(label, style="bold"))
                labeled = True
            else:
                cells.append(Text(""))
        return cells

    def update_status(self) -> None:
        n = len(self.data["rows"])
        parts = [f"{n} row{'s' if n != 1 else ''}"]
        pos = self.cur()
        if pos:
            c = self.data["columns"][pos[1]]
            parts.append(f"column: {c['name']}" + (" (hidden)" if c["secret"] else ""))
        elif not n:
            parts.append("press a to add your first row")
        sums, dollars = self.totals()
        if sums and n:
            parts.append("total: " + money_text(sum(sums.values(), Decimal(0)), any(dollars.values())))
        if self.reveal:
            parts.append("secrets visible")
        self.query_one("#status", Label).update("   ".join(parts))

    def on_data_table_cell_highlighted(self, event: DataTable.CellHighlighted) -> None:
        self.update_status()

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        if not self.readonly:
            self.action_edit()

    # -- small helpers --

    def cur(self) -> Optional[tuple[int, int]]:
        if not self.data["rows"] or not self.data["columns"]:
            return None
        dt = self.query_one(DataTable)
        if dt.cursor_row >= len(self.data["rows"]):
            return None  # the cursor is on the totals row
        return dt.cursor_row, dt.cursor_column

    def persist(self) -> None:
        # save the table to disk (encrypted) after every change
        self.vault.save_table(self.fid, self.data)

    # -- key actions --

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_redraw(self) -> None:
        # manual fix if the screen ever looks wrong
        self.app.refresh(layout=True)
        self.rebuild()

    def action_reveal(self) -> None:
        self.reveal = not self.reveal
        self.rebuild()

    def action_copy(self) -> None:
        pos = self.cur()
        if not pos:
            return
        value = self.data["rows"][pos[0]][pos[1]]
        try:
            self.app.copy_to_clipboard(value)
            self.notify("Copied to clipboard")
        except Exception:
            self.notify("Your terminal blocked clipboard access", severity="warning")

    def action_edit(self) -> None:
        pos = self.cur()
        if not pos:
            if not self.data["rows"]:
                self.notify("No rows yet, press a to add one")
            return
        r, c = pos
        col = self.data["columns"][c]

        def done(v: Optional[str]) -> None:
            if v is None:
                return
            self.data["rows"][r][c] = v
            self.persist()
            self.rebuild(r, c)

        self.app.push_screen(
            InputModal(f"Edit {col['name']}", self.data["rows"][r][c], generate=col["secret"]), done
        )

    def action_flip(self) -> None:
        pos = self.cur()
        if not pos:
            return
        r, c = pos
        v = self.data["rows"][r][c].strip().lower()
        if v in ("true", "false"):
            self.data["rows"][r][c] = "false" if v == "true" else "true"
            self.persist()
            self.rebuild(r, c)

    def action_add_row(self) -> None:
        defaults = ["false" if is_bool_column(c["name"]) else "" for c in self.data["columns"]]
        self.data["rows"].append(defaults)
        r = len(self.data["rows"]) - 1
        self.persist()
        self.rebuild(r, 0)
        self.fill(r, 0)

    def fill(self, r: int, c: int) -> None:
        # ask for each field of a new row one after another, esc stops early
        cols = self.data["columns"]
        if c >= len(cols):
            return
        col = cols[c]

        def done(v: Optional[str]) -> None:
            if v is None:
                return
            self.data["rows"][r][c] = v
            self.persist()
            self.rebuild(r, c)
            self.fill(r, c + 1)

        hint = "type true or false" if is_bool_column(col["name"]) else f"field {c + 1} of {len(cols)}, esc stops here"
        self.app.push_screen(
            InputModal(col["name"], self.data["rows"][r][c], hint=hint, generate=col["secret"]), done
        )

    def action_del_row(self) -> None:
        pos = self.cur()
        if not pos:
            return
        r = pos[0]
        label = next((v for v in self.data["rows"][r] if v), "this row")

        def done(yes: Optional[bool]) -> None:
            if yes:
                del self.data["rows"][r]
                self.persist()
                self.rebuild(r, None)

        self.app.push_screen(ConfirmModal(f"Delete row '{label}'?"), done)

    def action_add_col(self) -> None:
        def done(name: Optional[str]) -> None:
            if not name or not name.strip():
                return
            name = name.strip()
            self.data["columns"].append({"name": name, "secret": looks_secret(name)})
            fill = "false" if is_bool_column(name) else ""
            for row in self.data["rows"]:
                row.append(fill)
            self.persist()
            self.rebuild(None, len(self.data["columns"]) - 1)

        self.app.push_screen(InputModal("New column name"), done)

    def action_del_col(self) -> None:
        if len(self.data["columns"]) <= 1:
            self.notify("A table needs at least one column", severity="warning")
            return
        c = self.query_one(DataTable).cursor_column
        name = self.data["columns"][c]["name"]

        def done(yes: Optional[bool]) -> None:
            if yes:
                del self.data["columns"][c]
                for row in self.data["rows"]:
                    del row[c]
                self.persist()
                self.rebuild(None, c)

        self.app.push_screen(ConfirmModal(f"Remove column '{name}' and its data?"), done)

    def action_rename_col(self) -> None:
        c = self.query_one(DataTable).cursor_column
        col = self.data["columns"][c]

        def done(name: Optional[str]) -> None:
            if name and name.strip():
                col["name"] = name.strip()
                self.persist()
                self.rebuild(None, c)

        self.app.push_screen(InputModal("Rename column", col["name"]), done)

    def action_toggle_money(self) -> None:
        c = self.query_one(DataTable).cursor_column
        col = self.data["columns"][c]
        col["money"] = not is_money(col)
        self.persist()
        self.rebuild(None, c)
        self.notify(f"{col['name']} is {'counted in totals' if col['money'] else 'not counted'}")

    def action_toggle_secret(self) -> None:
        c = self.query_one(DataTable).cursor_column
        col = self.data["columns"][c]
        col["secret"] = not col["secret"]
        self.persist()
        self.rebuild(None, c)
        self.notify(f"{col['name']} is now {'hidden' if col['secret'] else 'plain'}")


# ---- app: styling and startup ----

class RotVaultApp(App):
    TITLE = "rotvault"

    # all the rounded, borderless-grid look comes from this CSS
    CSS = """
    LoginScreen, HomeScreen { align: center middle; }

    #card {
        width: 64;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 3;
    }
    .brand { text-style: bold; color: $accent; margin-bottom: 1; width: 100%; }
    .sub { color: $text-muted; margin-bottom: 1; width: 100%; }
    #msg { color: $error; height: 1; }

    Input { border: round $primary; background: transparent; margin-bottom: 1; }
    Input:focus { border: round $accent; }

    #tables {
        height: auto;
        max-height: 14;
        border: none;
        background: transparent;
        padding: 0;
    }

    #grid {
        height: 1fr;
        margin: 1 2 0 2;
        border: round $accent;
        border-title-color: $accent;
        border-title-style: bold;
        border-subtitle-color: $text-muted;
        background: $surface;
        padding: 0 1;
    }
    #grid DataTable { background: transparent; height: 1fr; }
    DataTable > .datatable--header { background: $surface; color: $accent; text-style: bold; }
    DataTable > .datatable--cursor { background: $accent 40%; color: $text; text-style: none; }
    #status { margin: 0 3; color: $text-muted; height: 1; }

    InputModal, ConfirmModal { align: center middle; background: $background 60%; }
    #dialog {
        width: 62;
        height: auto;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.vault = Vault(Path(os.environ.get("ROTVAULT_DIR", "~/.rotvault")))

    def on_mount(self) -> None:
        self.register_theme(ROT_THEME)
        self.theme = "rotvault"
        self.push_screen(LoginScreen(self.vault), self.after_login)

    def after_login(self, ok: Optional[bool]) -> None:
        if ok:
            self.push_screen(HomeScreen(self.vault))
        else:
            self.exit()


if __name__ == "__main__":
    RotVaultApp().run()
