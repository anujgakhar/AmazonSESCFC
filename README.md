AmazonSES CFC
=================

This CFC provides an interface to [Amazon Simple Email Service] (http://aws.amazon.com/ses/)

Setup
-----
Pass in your auth credentials to the CFC's init() method and start using it.

	ACCESS_KEY = "access_key";
	SECRET_KEY = "secret_key";

	objSes = createObject("component","com.anujgakhar.AmazonSES").init(
	accessKey="#ACCESS_KEY#", 
	secretKey="#SECRET_KEY#"
	);
	
### Verify an email Address

To verify an email address:
	
	objSes.verifyEmailAddress("your_email@address.com");	
	
	
### List Verified Email Addresses

To list all the verified email addresses on your account:

	objSes.listVerifiedEmailAddresses();	
	
### Delete a Verified Email Address

To delete one of your verified email addresses:

	objSes.deleteVerifiedEmailAddress("your_email@address.com");
	
### To get your Sending Quota

To get your quota:

	objSes.getSendQuota();	
	
### To get your Sending Statistics

To get your sending statistics:

	objSes.getSendStatistics();	
		
### To send an email

To send an email:
		
	args = {};
	args.to = [];
	arrayAppend(args.to,"recipient1@address.com");
	arrayAppend(args.to,"recipient2@address.com");
	args.from = "your_verified@address.com";
	args.subject = "Test Email via the API";
	args.messagetext = "This is the body of the email. This email is going out via the API";
	objSes.sendEmail(argumentCollection =  args);
	
	
