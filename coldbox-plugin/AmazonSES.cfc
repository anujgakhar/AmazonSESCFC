<!-----------------------------------------------------------------------
Amazon SES API Wrapper

Written by Anuj Gakhar (anuj.gakhar@gmail.com)

You will have to create some settings in your ColdBox configuration file:

ses_accessKey : The Amazon access key
ses_secretKey : The Amazon secret key

----------------------------------------------------------------------->
<cfcomponent hint="Amazon SES API Wrapper" output="false" extends="coldbox.system.Plugin" cache="true">
	
	<cfscript>
		this.host = "email.us-east-1.amazonaws.com";
		this.STATUS_OK = "ok";
	</cfscript>

<!------------------------------------------- CONSTRUCTOR ------------------------------------------>
	<cffunction name="init" access="public" returnType="AmazonSES" output="false" hint="Constructor">
		<cfargument name="controller" type="any"/>
		<cfscript>
			// Setup Plugin
			super.init(arguments.controller);
			setPluginName("Amazon SES API Wrapper");
			setPluginVersion("1.0");
			setPluginDescription("An API wrapper to the Amazon Simple Email service (SES)");
			setPluginAuthor("Anuj Gakhar");
			setPluginAuthorURL("http://www.anujgakhar.com");

			// Check settings
			if( not settingExists("ses_accessKey") ){
				$throw(message="ses_accesskey setting not defined, please define it.",type="ses.invalidSettings");
			}
			if( not settingExists("ses_secretKey") ){
				$throw(message="ses_secretKey setting not defined, please define it.",type="ses.invalidSettings");
			}

			// Setup Auth
			setAuth(getSetting("ses_accessKey"), getSetting("ses_secretKey"));
			setEndPointUrl();
			
			return this;
		</cfscript>
	</cffunction>

    <cffunction name="setAuth" output="false" access="public" returntype="void" hint="Set the Amazon credentials">
    	<cfargument name="accessKey" type="string" required="true" default="" hint="The amazon access key"/>
		<cfargument name="secretKey" type="string" required="true" default="" hint="The amazon secret key"/>
		<cfscript>
			instance.accessKeyID = arguments.accessKey;
			instance.secretAccessKey = arguments.secretKey;
		</cfscript>
    </cffunction>

   <cffunction name="setEndPointUrl" output="false" access="public" returntype="void" hint="Set the endpoint for AWS Email Service">
    	<cfargument name="host" type="string" required="false" default="#this.host#" hint="The endpoint for AWS Email Service"/>
    	<cfscript>
			instance.endPointUrl = "https://#arguments.host#";
			this.host = arguments.host;
		</cfscript>
    </cffunction>

<!------------------------------------------- PUBLIC ------------------------------------------>

	<cffunction name="verifyEmailAddress" output="false" access="public" returntype="struct" hint="Verifies an email address. This action causes a confirmation email message to be sent to the specified address">
		<cfargument name="emailAddress" required="true" type="string" default="" hint="The email address to be verified" />
		<cfscript>
			var results = {};
			var apiArgs = {};
			var apiCall = "";

			apiArgs.method = "POST";
			apiArgs.parameters = {};
			apiArgs.parameters['Action'] = "VerifyEmailAddress";
			apiArgs.parameters['EmailAddress'] = trim(arguments.emailAddress);

			apiCall = SESRequest(argumentCollection = apiArgs);

			if(!apiCall.error){
				results["data"] = "";
				results["status"] = this.STATUS_OK;
			} else {
				$throw("Error making Amazon SES Call", apiCall.message);
			}

			return results;
		</cfscript>		
	</cffunction>
	
	<cffunction name="deleteVerifiedEmailAddress" output="false" access="public" returntype="struct" hint="Deletes the specified email address from the list of verified addresses">
		<cfargument name="emailAddress" required="true" type="string" default="" hint="The email address to be deleted from the verified list" />
		<cfscript>
			var results = {};
			var apiArgs = {};
			var apiCall = "";

			apiArgs.method = "DELETE";
			apiArgs.parameters = {};
			apiArgs.parameters['Action'] = "DeleteVerifiedEmailAddress";
			apiArgs.parameters['EmailAddress'] = trim(arguments.emailAddress);

			apiCall = SESRequest(argumentCollection = apiArgs);

			if(!apiCall.error){
				results["data"] = "";
				results["status"] = this.STATUS_OK;
			} else {
				$throw("Error making Amazon SES Call", apiCall.message);
			}

			return results;
		</cfscript>		
	</cffunction>

	<cffunction name="listVerifiedEmailAddresses" output="false" access="public" returntype="struct" hint="Returns a list containing all of the email addresses that have been verified">
		<cfscript>
			var results = {};
			var verifiedEmailAddresses = [];
			var apiArgs = {};
			var apiCall = "";

			apiArgs.method = "GET";
			apiArgs.parameters = {};
			apiArgs.parameters['Action'] = "ListVerifiedEmailAddresses";

			apiCall = SESRequest(argumentCollection = apiArgs);

			if(!apiCall.error){
				emailsXML = xmlSearch(apiCall.response, "//:member");
				for(x=1; x lte arrayLen(emailsXML); x++){
					thisEmail = trim(emailsXML[x].xmlText);
					arrayAppend(verifiedEmailAddresses, thisEmail);
				}
				results["data"] = verifiedEmailAddresses;
				results["status"] = this.STATUS_OK;
			} else {
				$throw("Error making Amazon SES Call", apiCall.message);
			}

			return results;
		</cfscript>		
	</cffunction>

	<cffunction name="getSendQuota" output="false" access="public" returntype="struct" hint="Returns the user's current sending limits">
		<cfscript>
			var apiArgs = {};
			var apiCall = "";
			var results = {};
			var quotaResults = {};

			apiArgs.method = "GET";
			apiArgs.parameters = {};
			apiArgs.parameters['Action'] = "GetSendQuota";

			apiCall = SESRequest(argumentCollection = apiArgs);

			if(!apiCall.error){
				quotaXML = xmlSearch(apiCall.response, "//:GetSendQuotaResult");
				for(x=1; x lte arrayLen(quotaXML[1].XmlChildren); x++){
					thisQuota = quotaXML[1].XmlChildren[x];
					quotaName = trim(thisQuota.XmlName);
					quotaValue = trim(thisQuota.XmlText);
					quotaResults[quotaName] = quotaValue;
				}
				results["data"] = quotaResults;
				results["status"] = this.STATUS_OK;
			} else {
				$throw("Error making Amazon SES Call", apiCall.message);
			}

			return results;
		</cfscript>		
	</cffunction>

	<cffunction name="getSendStatistics" output="false" access="public" returntype="struct" hint="Returns the user's sending statistics. The result is a list of data points, representing the last two weeks of sending activity">
		<cfscript>
			var apiArgs = {};
			var apiCall = "";
			var results = {};
			var dataPoints = [];

			apiArgs.method = "GET";
			apiArgs.parameters = {};
			apiArgs.parameters['Action'] = "GetSendStatistics";

			apiCall = SESRequest(argumentCollection = apiArgs);

			if(!apiCall.error){
				dataPointsXML = xmlSearch(apiCall.response, "//:member");
				for(x=1; x lte arrayLen(dataPointsXML); x++){
					thisDataPoint = dataPointsXML[x].XmlChildren;
					dataPointDetails = {};
					for(y=1; y lte arrayLen(thisDataPoint); y++){
						thisDetailName = thisDataPoint[y].XmlName;
						thisDetailValue = thisDataPoint[y].XmlText;
						dataPointDetails[thisDetailName] = thisDetailValue;
					}
					arrayAppend(dataPoints, dataPointDetails);
				}
				results["data"] = dataPoints;
				results["status"] = this.STATUS_OK;
			} else {
				$throw("Error making Amazon SES Call", apiCall.message);
			}

			return results;
		</cfscript>		
	</cffunction>

	<cffunction name="sendEmail" output="false" access="public" returntype="struct" hint="Composes an email message based on input data, and then immediately queues the message for sending">
		<cfargument name="to" required="true" type="array" hint="email addresses to be used in the TO field" />
		<cfargument name="cc" required="false" type="array" hint="email addresses to be used in the CC field" />
		<cfargument name="bcc" required="false" type="array" hint="email addresses to be used in the BCC field" />
		<cfargument name="replyto" required="false" type="array" hint="The reply-to email address(es) for the message. If the recipient replies to the message, each reply-to address will receive the reply" />
		<cfargument name="from" required="true" type="string" hint="The sender's email address" />
		<cfargument name="subject" required="false" type="string" hint="subject of the email" />
		<cfargument name="subjectCharset" required="false" type="string" hint="Charset of the subject" default="utf-8" />
		<cfargument name="returnpath" required="false" type="string" hint="The email address to which bounce notifications are to be forwarded. If the message cannot be delivered to the recipient, then an error message will be returned from the recipient's ISP; this message will then be forwarded to the email address specified by the ReturnPath parameter" />
		<cfargument name="messagetext" required="true" type="string" hint="message of the email" />
		<cfargument name="messagetextCharset" required="false" type="string" hint="message of the email" />
		<cfargument name="messagehtml" required="false" type="string" hint="html message" />
		<cfargument name="messagehtmlCharset" required="false" type="string" hint="Charset of the html message" />
		<cfscript>
			var apiArgs = {};
			var apiCall = "";
			var results = {};

			apiArgs.method = "POST";
			apiArgs.parameters = {};
			apiArgs.parameters['Action'] = "SendEmail";

			for(i=1; i lte arraylen(arguments.to); i++){
				apiArgs.parameters['Destination.ToAddresses.member.#i#'] = trim(arguments.to[i]);
			}

			if(structKeyExists(arguments,"cc") and IsArray(arguments.cc)){
				for(j=1; j lte arraylen(arguments.cc); j++){
					apiArgs.parameters['Destination.CcAddresses.member.#j#'] = trim(arguments.cc[j]);
				}
			}

			if(structKeyExists(arguments,"bcc") and IsArray(arguments.bcc)){
				for(k=1; k lte arraylen(arguments.bcc); k++){
					apiArgs.parameters['Destination.BccAddresses.member.#k#'] = trim(arguments.bcc[k]);
				}
			}

			if(structKeyExists(arguments,"replyto") and IsArray(arguments.replyto)){
				for(m=1; m lte arraylen(arguments.replyto); m++){
					apiArgs.parameters['ReplyToAddresses.member.#m#'] = trim(arguments.replyto[m]);
				}
			}

			apiArgs.parameters['Source'] = trim(arguments.from);

			if(structKeyExists(arguments,"returnpath") and len(trim(arguments.returnpath))){
				apiArgs.parameters['ReturnPath'] = trim(arguments.returnpath);
			}

			if(structKeyExists(arguments,"subject") and len(trim(arguments.subject))){
				apiArgs.parameters['Message.Subject.Data'] = trim(arguments.subject);
				if(structKeyExists(arguments,"subjectCharset") and len(trim(arguments.subjectCharset))){
					apiArgs.parameters['Message.Subject.Charset'] = trim(arguments.subjectCharset);
				}	
			}

			if(structKeyExists(arguments,"messagetext") and len(trim(arguments.messagetext))){
				apiArgs.parameters['Message.Body.Text.Data'] = trim(arguments.messagetext);
				if(structKeyExists(arguments,"messagetextCharset") and len(trim(arguments.messagetextCharset))){
					apiArgs.parameters['Message.Body.Text.Charset'] = trim(arguments.messagetextCharset);
				}	
			}

			if(structKeyExists(arguments,"messagehtml") and len(trim(arguments.messagehtml))){
				apiArgs.parameters['Message.Body.Html.Data'] = trim(arguments.messagehtml);
				if(structKeyExists(arguments,"messagehtmlCharset") and len(trim(arguments.messagehtmlCharset))){
					apiArgs.parameters['Message.Body.Html.Charset'] = trim(arguments.messagehtmlCharset);
				}	
			}

			apiCall = SESRequest(argumentCollection = apiArgs);

			if(!apiCall.error){
				sendEmailXMl = xmlSearch(apiCall.response, "//:MessageId");
				if(arraylen(sendEmailXML)){
					results["data"] = {};
					results["data"]["MessageId"] = sendEmailXMl[1].XmlText;
				} else {
					results["data"] = "";
				}
				results["status"] = this.STATUS_OK;
			} else {
				$throw("Error making Amazon SES Call", apiCall.message);
			}

			return results;
		</cfscript>		
	</cffunction>

<!------------------------------------------- PRIVATE ------------------------------------------>
    <cffunction name="SESRequest" output="false" access="private" returntype="struct" hint="Invoke an Amazon REST Call">
    	<cfargument name="method" type="string" required="false" default="GET" hint="The HTTP method to invoke"/>
		<cfargument name="parameters" type="struct" required="false" default="#structNew()#" hint="An struct of HTTP URL parameters to send in the request"/>
		<cfargument name="timeout" type="numeric" required="false" default="20" hint="The default call timeout"/>
		<cfscript>
			var results = {};
			var HTTPResults = "";
			var timestamp = GetHTTPTimeString(Now());
			var sortedParams = listSort(structKeyList(arguments.parameters), "textnocase");
			var paramtype = "URL";

			if(arguments.method eq "POST"){
				paramtype = "FORMFIELD";
			}

			results.error = false;
			results.response = {};
			results.message ="";
			results.responseheader = {};
			
			signature = createSignature(timestamp);
		</cfscript>

		<cfif not structKeyExists(instance, "endPointUrl") or not len(trim(instance.endPointUrl))>
			<cfthrow message = "EndPointUrl not defined" type="ses.invalidhost" />
		</cfif>

		<cfhttp method="#arguments.method#"
				url="#instance.endPointUrl#/"
				charset="utf-8"
				result="HTTPResults"
				timeout="#arguments.timeout#">

			<cfhttpparam type="header" name="Date" value="#timestamp#" />
			<cfhttpparam type="header" name="Host" value="#this.host#" />
			<cfhttpparam type="header" name="X-Amzn-Authorization" value="AWS3-HTTPS AWSAccessKeyId=#instance.accessKeyID#,Algorithm=HmacSHA256,Signature=#signature#" />

			<cfloop list="#sortedParams#" index="param">
				<cfhttpparam type="#paramType#" name="#param#" value="#trim(arguments.parameters[param])#" />
			</cfloop>
		</cfhttp>

		<cfscript>
			log.debug("Amazon SES Call ->Arguments: #arguments.toString()#, ->Encoded Signature=#signature#", HTTPResults);
			
			if(structKeyExists(HTTPResults,"fileContent"))
			{
				results.response = HTTPResults.fileContent;
			} else {
				results.response = "";
			}
			results.responseHeader = HTTPResults.responseHeader;
			results.message = HTTPResults.errorDetail;
			if( len(HTTPResults.errorDetail) ){ results.error = true; }

			if( structKeyExists(HTTPResults.responseHeader, "content-type") AND
			    HTTPResults.responseHeader["content-type"] eq "text/xml" AND
				isXML(HTTPResults.fileContent) ){
				results.response = XMLParse(HTTPResults.fileContent);
				// Check for Errors
				if( NOT listFindNoCase("200,204",HTTPResults.responseHeader.status_code) ){
					// check error xml
					results.error = true;
					results.message = "Type:#results.response.errorresponse.error.Type.XMLText# Code: #results.response.errorresponse.error.code.XMLText#. Message: #results.response.errorresponse.error.message.XMLText#";
				}
			}

			return results;
		</cfscript>
	</cffunction>

	<cffunction name="createSignature" returntype="any" access="private" output="false" hint="Create request signature according to AWS standards">
		<cfargument name="stringToSign" type="any" required="true" />
		<cfscript>
			var fixedData = replace(arguments.stringToSign,"\n","#chr(10)#","all");
			return toBase64(HMAC_SHA256(instance.secretAccessKey,fixedData) );
		</cfscript>
	</cffunction>

	<cffunction name="HMAC_SHA256" returntype="binary" access="private" output="false" hint="">
		<cfargument name="signKey"     type="string" required="true" />
	   	<cfargument name="signMessage" type="string" required="true" />
	   	<cfscript>
			var jMsg = JavaCast("string",arguments.signMessage).getBytes("utf-8");
			var jKey = JavaCast("string",arguments.signKey).getBytes("utf-8");
			var key = createObject("java","javax.crypto.spec.SecretKeySpec").init(jKey,"HmacSHA256");
			var mac = createObject("java","javax.crypto.Mac").getInstance(key.getAlgorithm());
			mac.init(key);
			mac.update(jMsg);
			return mac.doFinal();
	   	</cfscript>
	</cffunction>
</cfcomponent>