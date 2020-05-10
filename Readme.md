Create your own ad block proxy profile, install it and modify it by @HiMyNameIsUbik

If this guide helped you out or you have a question, feel free to follow me on Twitter :)

Get the EasyList PAC

A1. Fork the EasyList PAC Repo: https://github.com/essandess/easylist-pac-privoxy

A2. Get your PAC URL and store it in a text file: https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/easylist-pac-privoxy/master/proxy.pac

A3. Generate 3 Version 1 UUIDs and store them in a text file: https://www.uuidgenerator.net/version1

A4. Create your own mobile config with this template by copy pasting the contents in a text file and replacing the commented strings with your UUIDs from #A3 and the rest: https://pastebin.com/raw/gLxYVLDL

A5. Save your file as PAC.mobileconfig on your desktop.
Host mobile config on GitHub

B1. Go to your forked EasyList PAC Repo: https://github.com/YOUR_GITHUB_USERNAME/easylist-pac-privoxy

B2. Click on "Create a new file" and name it PAC.mobileconfig.

B3. Copy & paste the contents of your PAC.mobileconfig file from #A5.

B4. Commit the new file.

B5. Your mobile config should now be available here: https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/easylist-pac-privoxy/master/PAC.mobileconfig
Host on your own server

C1. Connect to your web server

C2. Upload your "PAC.mobileconfig" file from #A5.

C3. Your mobile config should now be available here: https://YOUR_DOMAIN/PAC.mobileconfig
Install your mobile config

D1. Add repo https://repo.syns.me or https://repo.sukarodo.me and install iSupervisor. (Use Cydia)
D2. Reboot your device or run Ldrestart. (If you skip this you will get an error)
D3. Open the URL from #B5 or #C3 and install the profile.
D4. To remove the notification at the top of your settings app saying "This device is supervised" uninstall iSupervisor using Cydia/Zebra/etc. If the notification is still there after uninstalling follow #D5 else skip to #D7.
D5. Navigate to /var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles and open CloudConfigurationDetails.plist
D6. Replace <key>IsSupervised</key><true/> with <key>IsSupervised</key><false/>
D7. Reboot
D8. ???
D9. Profit
Modify blocked ads and trackers

E1. Go to your forked EasyList PAC Repo: https://github.com/YOUR_GITHUB_USERNAME/easylist-pac-privoxy
E2. Open the file proxy.pac
E3. Click on the pencil icon to start editing your file
E4. Scroll to bad_da_host_JSON (currently on line #236)
E5. Add your desired url to block on the next line (#237 for example) in this format "url.com": null,. Be careful to exactly format it as shown else you might break your proxy.pac file.
E6. Add more (?)
E7. To save your changes click on the green button "Commit changes".
E8. Since your mobile config links to this file it will automatically block the newly added urls.
