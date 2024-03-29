# Password Manager
zy (at) zyisrad (dot) com

This is a Password manager for the command line interface. Linux only. It utilizes [libsodium](http://doc.libsodium.org/) found at http://doc.libsodium.org/

## Requirements

* libsodium
* ncurses
* sudo

## Commands
```
new            Create a new entry
edit           Edit an existing entry
delete,del     Remove an existing entry
list,ls        List current entries
get            Get an entry and view it
change         Change password
backup         Backup to tar
exit           Exit application
```

After getting root priveleges(for chattr), it will create the folder ".pbox" in your user folder(/home/<user>/.pbox/). It will then create ".list" and ".pandorasBox" in that folder. ".list" holds your passwords and ".pandorasBox" holds your secrets.

To encrypt your data, a secret is created from your password and some salt. Your password and secret are hashed and stored. The salt is stored unencrypted. To unlock the secret, you recreate the secret with your password and the salt each time you open the application. Then it is verified with the hashed version of the secret.

The titles are all decrypted and stored in memory while the username and passwords remain encrypted in memory. The username and passwords are decrypted only when needed to view or edit.

The title, username, and password are each stored encrypted on a line in ".list" as a message length, nonce, and encrypted data. Authentication is built into the encrypted messages to ensure the data isn't tampered with(Thanks libsodium! ;) ).

Using a detached thread, a timer will automatically and gracefully exit if idle for 30 seconds. This will ensure the unecrypted data is zeroed and the user doesn't accidentally leave it running. The timer is restarted after each command is entered.

## Installation/Testing

```
//Make an executable named "test" in the current folder
make
//Make and executable named "pbox" in /usr/bin
sudo make install
```