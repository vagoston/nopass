# Passwordless authentication (concept)
## Disclaimer:
This is a concept. I think it's easier to understand my concept by reading code, but that code is not meant to be use in production.
## The problem
Passwords are evil. In several different way. They are weak, unfortunately humans suck in finding out and memorizing good passwords. Different strong password for each and every site? Are you kidding with me? So, there are two common improvement. One of them is two factor authentication/tokens, the other one is password managers/oauth. What is my problem with these?
### Tokens:
In general tokens are good, my concept is basically uses a device as a token. I have two factor auth turned on wherever I can. (I hpoe you too.) Have you ever lost your phone? If you have, you probably realised the most critical problems. A: you can reset your settings and get a new token. B: Your email/phone/whatever is a weak link, there is a way to access your account with some kind of information, and usually these information accessible by your phone
### Password managers
You actually reduce the number of passwords, and that's good, but at the end of the day you'll have one (weak) password. Either it has a weak link to recover your password, or not. Both of that is problematic. 
## Solution
Public/private keys are good solution. (I think the best until quantum crypto is accessible.) We need to solve a couple of problems. Some of them are ergonomic problems, some of them are technical. What I would like in case my mobile (token) is lost:
* I want to invalidate/inactivate my token (at least temporarily)
* I want to access all encrypted information
* I want some kind of authentication that proves that I am the rightful owner of my lost key
Who would identify me in a trustworthy way? Would you trust a biometric identification for that? (I would not.) Would you trust some kind of buro for that? (I would not.) Would you trust some of your friends/family members? (I would.) Anyway, you need to trust someone.
How could someone store my key in a way that it remains recoverable, but not accessible by anyone? Let's say your trust 5 people, so they would not let others access your data. They don't even need to know that they are your keykeeper. You can encode your private key with their the public keys and upload that to a storage. 
### Process
* Register: A key is generated, public key is uploaded to server
* Login: You visit a webpage to log in. A one-time key (currently the session id) is generated and displayed. This key should be signed with you private key, this signature is posted to the server, that will log you in to your session.
* Fraud detection: Every time a client communicating with the server, a new random number is generated. This need to submitted with the next message. This way, even if your key is revealed, you are going to notice this next time you try to log in. Your account is set as compromised.
* Invalidation: Anyone who is your keykeeper can invalidate your account.
* Re-validation: In case invalidation happened by a mistake or a misunderstanding, you keykeepers can re-enable your account.
* Restore: First of all, you need to generate and register a new key. Your old key can be restored with the help of any three of your five keykeeprs. They wil not access your old key, not even on the server. Your keykeepers with decrypt a symmetric key and encrypt it with your new public key. At the end of this process you will have three keys for the Reed-Solomon blocks of your old private key. You can download, decrypt, restore your old key. With the help of that you can access you private data. Just download, decrypt with old key, encrypt with new key and upload it.
