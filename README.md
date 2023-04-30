# microsoft-smtp-xoauth2-test-tool
This is a test tool for SMTP XOAUTH2 email workflow. This is using the device code flow of OAuth2 for limited input devices. This will test if Microsoft side did some breakage so that they can fix issues immediately.


How to use this tool

cargo run \<client id\> \<sender email address\> \<sender name\> \<recipient email\> \<recipient name\> \<debug log level\>

The debug log level can be of the following:
- error
- warn
- info
- debug
- trace

Just look in the logs on the user code that you need to input in the cloud to login your outlook account to get the access token that will be used for SMTP XOAUTH2. Since this is a device code flow way for limited input devices, that is why you need that work flow.
