# InstanceSniper
By "lumi_vrc" on Discord, "- Lumine -" in game.
This bot will automatically close VRChat instances "illegally" opened via exploits.

Install dependencies with npm install.

Then, simply run instanceSniper.js with pm2 or as a standalone process in a terminal, coupled with a group id to insert it in the database.

Bot account must be in group with "View Audit Log", "View All Members", and "Manage Group Instances" permissions.
Usage:
node instancesniper.js grp_xxx


/config/db.json
```json
{
    "host": "localhost",
    "port": "3306",
    "user": "Username",
    "password": "Password",
    "database": "instanceSniperDB"
  }
  ```
Replace Username and Password with whatever mySQL login was used to create the listed database, which you also need to create.

/config/credentials.json
```json
{
    "VRChat": {
      "email": "email@email.com",
      "pass": "password",
      "twofa": "two factor auth seed (SEE README)"
    }
  }
  ```
Email and pasword self explanatory.
Obtain your 2fa auth seed by following these instructions:
1. Go to your VRChat profile settings.
2. Enable 2FA (or disable and re-enable if active).
3. Hover camera over QR code (Do not follow link yet)
4. Manually inspect link for "YOURCODEISHERE":
otpauth://totp/VRChat:email@email.com?secret=YOURCODEISHERE&issuer=VRChat
5. Save that in "twofa", then follow the link and complete 2FA setup normally.
