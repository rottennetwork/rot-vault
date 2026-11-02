# rotvault

A small encrypted table app for the terminal. Make tables like a password list, add or remove columns whenever you want, and everything is saved encrypted under random file names.

I created this for myself, but wanted to make a full open-source github repo. this will forever remain fully open-source.

When I get to the API Integration, I will have full documentation on how to use it edit it and have it be as you need.


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
| s | reveal hidden values |
| c | copy the selected cell |
| Space | flip a true/false cell |
| Esc | back to the list |

Columns with names like password, token or pin are hidden by default. While editing one, press `ctrl+g` to generate a strong password.

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





## Future Plans

- API Intergration
- Discord Bot Intergration
- Custom Encryption
