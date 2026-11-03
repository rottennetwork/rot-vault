# rotvault

A small encrypted table app for the terminal. Make tables like a password list, add or remove columns whenever you want, and everything is saved encrypted under random file names.

## Install

```
pip install textual cryptography
```

## Run

```
python rotvault.py
```

The first time, you create a master password. There is no recovery if you forget it.

## How to use

Pick a table from the list, or choose **+ New table** and give it a name and some columns (comma separated). The default is `Emails, Passwords, Application, 2AUTH`.

**Table list**

| Key | Action |
| --- | --- |
| Enter | open and edit |
| v | open view only |
| n | new table |
| r | rename |
| d | delete |
| q | quit |

**Inside a table**

| Key | Action |
| --- | --- |
| a | add a row |
| e or Enter | edit the selected cell |
| d | delete the row |
| n | add a column |
| x | remove the column |
| r | rename the column |
| t | hide or show a column's values |
| m | count a column in the totals (or stop counting it) |
| s | reveal hidden values |
| c | copy the selected cell |
| Space | flip a true/false cell |
| Ctrl+L | redraw the screen if it ever looks wrong |
| Esc | back to the list |

Columns with names like password, token or pin are hidden by default. While editing one, press `ctrl+g` to generate a strong password.

## Totals

Any column with price, cost or a $ in its name is added up automatically. The sums show in a bold row at the bottom, right under each column, and the combined total is shown on the left and in the status line.

```
item   link       price    upgrades   price2
1      test.com   $1200    mount      $200
2      test.com   $200     pad        $50
total: $1,650      $1,400              $250
```

- Numbers can be written as `1200`, `$1,200` or `$12.50`. Blank cells and text are skipped.
- The totals row is worked out on the fly and never saved, so old tables work as they are.
- Press `m` on any column to add it to the totals or take it out.

## Where your data goes

Everything is saved in `~/.rotvault`. Change the location with the `ROTVAULT_DIR` environment variable:

```
ROTVAULT_DIR=/path/to/folder python rotvault.py
```

To back up, copy the whole folder, including the hidden `.salt` file. Without it nothing can be decrypted.

## Security

- Files are encrypted with AES-256-GCM.
- The key comes from your master password using scrypt.
- File names are random, and real table names exist only inside the encrypted index.
- It protects files at rest. It does not protect against malware on your computer.
