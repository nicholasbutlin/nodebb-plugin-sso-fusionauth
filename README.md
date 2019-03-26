# NodeBB OAuth SSO

NodeBB Plugin that allows users to login/register via any configured OAuth provider. **Please note** that this is not a complete plugin, but merely a skeleton with which you can create your own OAuth SSO plugin for NodeBB (and hopefully share it with others!)

## How to Adapt

1. Fork this plugin
   - ![](http://i.imgur.com/APWHJsa.png)
1. Add the OAuth credentials (around line 30 of `library.js`)
1. Update profile information (around line 137 of `library.js`) with information from the user API call
1. Clone the plugin folder to the node_modules folder of your NodeBB installation.
1. Activate this plugin from the plugins page
1. Restart your NodeBB
1. Let NodeBB take care of the rest

## Trouble?

## Note

THis provides login of the user lready exists

TODO: Create user if not exists
TODO: Logout user fully on logout not yet working
TODO: ACP login with SSO
