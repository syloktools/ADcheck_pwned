# ADcheck_pwned
PowerShell script to check AD for matching emails in a long list of emails and then query haveibeenpwned.com for matching hits


Requires a text file of email address to bounce against Active Directory, it will place the valid email addresses in a text file you specify.

Then it will do an API call to haveibeenpwned.com to check to see if information is available on which data breeches the email address could be involved in. This is pulled down in JSON, converts that to PS-CustomObjects and inserts them into a csv. It cleans up the JSON files.

So the script validates the emails exist in your AD and then give you the most relevant data dumps that could be the source of compromise. Helps when you get those big spreadsheets of compromised emails from your “Threat Intelligence” vendors.

Work in progress of course. 
