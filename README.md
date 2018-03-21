# Passwordless authentication (concpept)
## Disclaimer:
This is a concept. I think that it's easier to understand my concept by reading code, but that code is not meant to be use in production.
## The problem
Passwords are evil. In several different way. They are weak. Unfortunately humans suck in finding out and memorizing good passwords. Different strong password for each and every site? Are you kidding with me? So, there are two common improvement. One of them is two factor authentication/tokens, the other one is password managers/oauth. What is my problem with these?
### Tokens:
In general tokens are good, my concept is basically uses a devcice as a token. I have two factor auth turned on wherever I can. I hpoe you too. Have you ever lost your phen? If you do, you probably realized the most critical problems. A: you can reset your settings and get a new tokeb. B: Your email/phone/whatever is a weak link, there is a way to access your account with some kind of information, and usually these information accessible by your phone
### Passwrod managers
You actually reduce the number of passwords, and that's good, but at the end of the they you'll have one (weak) password. Either it has a weak link to recover your password, or not. Both of that is problematic.
## Solution
Public/private keys are good solution. (I think the best until quantum crypto is accessible.) We need to solve a couple of problems. Some of them are ergonomic problems, some of them are technical. What I would like in case my mobile (token) is lost:
* I want to invalidate/inactivate my token (at least temporarily)
* I want to access all encrypted information 
* I want some kind of authentication that proves that I am the rightful owner of my lost key
Who would identify me in a trustworthy way? Would you trust a biometric identification for that? (I would not.) Would you trust some kind of buro for that? (I would not.) Would you trust some of your friends/family members? (I would.) Anyway, you need to trust someone.
How could someone store my key that is recoverable, but not accessible by anyone? Let's say your trust 5 people, and you sey that if someone in the future can convience them to allow access to your data it's going to be you, or your rightful heir. They don't even need to know that they are your keykeeper. You can encode your private key with all triplets of the public keys of the five trusted people, and upload that to a storage. Also any of them can (temporarily) block your key, the majority of them can restore. If you want to change these settings, you need to wait a day. 
### Methods
For registration client generates a keypair, and sends that to the server.
They way you can be authenticated is based on a signiture, your device have to sign a generated one time id (session id) and send it back to the server for validation.
Optional confirmation: Before actual login, your device requests a user id from the server. This helps to prevent the event that someone else logs in to that session.
Ways to send information to a trusted device: QR code or audio encoding.