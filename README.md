# ssh-keygen-brain

Generate "brain keys" for use with OpenSSH.

# Why?

Suppose you have one (or, preferably, several) storage VPS machines on which you keep your backups. You want to SSH into these machines securely, using a keypair. However, if you lose your local data, along with the SSH private key, you won't be able to access your backups. Now you might think of saving the private key on a large number of flash drives or recordable DVD disks. `ssh-keygen-brain` gives you a better option: Given a passphrase, `ssh-keygen-brain` will deterministically generate an OpenSSH ed25519 private key file. Thus you need only know the passphrase to recover the private key at any time.

# Recipe

```
mkdir -p /tmp/ssh-key-brain-tour
cd /tmp/ssh-key-brain-tour
git clone https://github.com/AndreiBorac/ssh-keygen-brain.git
cd ./ssh-keygen-brain
bundle install --path vendor/bundle
./ssh-keygen-brain.rb >./kp
```

This above step is where you enter your super secret passphrase. It should output the private key. Now all that is left is to permission the file and calculate the public key.

```
chmod 0600 ./kp
ssh-keygen -y -f ./kp >./kp.pub
```
