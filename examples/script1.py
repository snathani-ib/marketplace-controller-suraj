import urllib3, json, base64
import os, time
import boto3
import secrets #to remove? this id is not tracked

# Send Slack notification based on the given message
def slack_notification(message):

    slack_webhook_url = os.environ['slack_webhook_url']
    try:
        slack_message = {'text': message}

        http = urllib3.PoolManager()
        response = http.request('POST',
                                slack_webhook_url,
                                body = json.dumps(slack_message),
                                headers = {'Content-Type': 'application/json'},
                                retries = False)
    except:
        traceback.print_exc()

    return True
def get_appdirect_token(key, secret):
    #marketplace_tokens
    #Store token in DynamoDB
    #{"access_token":"HuTTFof3yJWfz132fP-YjLwpEUsE0X__zr36wtUOrG9Xwg","token_type":"bearer","expires_in":43199,"scope":"ROLE_PARTNER_READ"}
    db = boto3.client('dynamodb')
    dbdata = db.scan(TableName='marketplace_tokens')
    #print(json.dumps(dbdata))
    if not dbdata["Items"]:
        appdirect_token_url="https://infoblox.byappdirect.com/oauth2/token"
        http = urllib3.PoolManager()
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
        headers.update(urllib3.make_headers(basic_auth=key+":"+secret))
        response = http.request('POST',
                                appdirect_token_url,
                                body = "grant_type=client_credentials&scope=ROLE_PARTNER_READ",
                                headers = headers,
                                retries = False)
        print ("Got token from appdirect")
        token=json.loads(response.data)['access_token']
        ttl=int(json.loads(response.data)['expires_in'])-1
        dbdata = db.put_item(TableName='marketplace_tokens',Item={'token': {'S': token},'ttl': {'N': str(ttl + int(time.time()))},})
        #print(response.data)
    else:
        print ("Got token from DynamoDB")
        token=dbdata['Items'][0]['token']['S']
    return token

def pull_appdirect_event(URL,token):
    http = urllib3.PoolManager()
    response = http.request('GET',
                            URL,
                            headers = {'Authorization': 'Bearer '+token, 'Accept':'application/json'},
                            retries = False)
    print(URL,token ,response.data, response.status)
    return json.loads(response.data)

#### these provisioning functions are expected to be with every marketplace integration
#### Store subscriptionId and API key in dynamodb

def manage_generic_subscription(webhook_template,integration,payload,onoff): #onoff - true/false
    ### generic workflow to create a webhook + subscription
    http = urllib3.PoolManager()
    db = boto3.client('dynamodb')

    if onoff:
        response = http.request('POST',
                                "https://csp.infoblox.com/atlas-notifications-config/v1/channel",
                                headers = {'Authorization': 'Token token='+payload['configuration']["csp_api_key"]},
                                body = json.dumps(webhook_template),
                                retries = False)
        #print(response.data)
        #add try handle etc
        #b'{"error":[{"message":"Service integration with the name \\"Marketplace: BloxOne Telegram management and notifications. Installed by: vpavlov+csp@infoblox.com\\" already exists"}]}'
        notification_id=json.loads(response.data)["result"]["id"]
        print ("New notification:",notification_id)
    else:
        dbdata=db.get_item(TableName='subscriptions',Key={'subscription_id': {'S': payload['configuration']["subscriptionId"]}})
        print(json.dumps(dbdata))
        print (payload['configuration']["subscriptionId"])
        notification_id=dbdata['Item']['notification_id']['S']
        payload['configuration']["csp_api_key"]=dbdata['Item']['apikey']['S']
        payload['configuration']['b1_notifications']="account, ddimetrics, host, service, newrelease"
        #get_item
        print ("Existing notification:",notification_id)
    ###Enable/disable notifications for the new subscription
    all_notifications={"Account Notifications":"account", "DDI Metrics":"ddimetrics", "Host Notifications":"host", "Service Notifications":"service", "New Release Notifications":"newrelease", "The Insightful Reporting system":"insights"}
    set_notifications=payload['configuration']['b1_notifications'].replace(', ', ' ').replace(',', ' ').replace('  ', ' ').split()
    response = http.request('GET',
                            "https://csp.infoblox.com/atlas-notifications-config/v1/notifications_delivery",
                            headers = {'Authorization': 'Token token='+payload['configuration']["csp_api_key"]},
                            retries = False)
    notifications_delivery = json.loads(response.data)["results"]
    #print (json.dumps(notifications_delivery)[0:100])
    for idx,subsrc in enumerate(notifications_delivery["subscriptions"]):
        if (subsrc["description"] == "Service Integrations"):
            for idy,n1 in enumerate(subsrc["notifications"]):
                #print (idx,idy,n1["notifications_type"])
                if (all_notifications[n1["notifications_type"]] in set_notifications):
                    for idz, delvry in enumerate(n1["delivery"]):
                        if (delvry["channel_id"] == notification_id):
                            #print ("seting",idx,idy,idz,notifications_delivery["subscriptions"][idx]['notifications'][idy]["delivery"][idz]["active"])
                            notifications_delivery["subscriptions"][idx]['notifications'][idy]["delivery"][idz]["active"]=onoff
                            #print ("set",idx,idy,idz,notifications_delivery["subscriptions"][idx]['notifications'][idy]["delivery"][idz]["active"])
    response = http.request('PUT',
                            "https://csp.infoblox.com/atlas-notifications-config/v1/notifications_delivery",
                            headers = {'Authorization': 'Token token='+payload['configuration']["csp_api_key"]},
                            body = json.dumps(notifications_delivery),
                            retries = False)
    #print (response.data) -- returns {}
    if onoff:
        #store new notification
        dbdata = db.put_item(TableName='subscriptions',Item={'subscription_id': {'S': payload['configuration']["subscriptionId"]},
                                                             'notification_id': {'S': notification_id},
                                                             'apikey': {'S': payload['configuration']["csp_api_key"]},})
    #delete old notification
    else:
        #delete notificaiton
        response = http.request('DELETE',
                                "https://csp.infoblox.com/atlas-notifications-config/v1/channel/"+notification_id,
                                headers = {'Authorization': 'Token token='+payload['configuration']["csp_api_key"]},
                                retries = False)
        db.delete_item(TableName='subscriptions',Key={'subscription_id': {'S': payload['configuration']["subscriptionId"]}})
    return True

def subs_create_slack(integration,payload):
    print ("Provisioning Slack")
    webhook_template={
        "name": "Marketplace: BloxOne Slack notifications. Installed by: "+payload["creator"]+" id: "+payload['configuration']["subscriptionId"],
        "created_by": "Marketplace integration installed by: "+payload["creator"]+" subscription: "+payload['configuration']["subscriptionId"],
        "channel_type_id": "8d69f684-e70e-4ab1-9eae-39f034cf2045",
        "config": {
            "authentication": {"type": "None"},
            "url": payload['configuration']["webhook"]
        },
        "template": "{\n\t\"text\": \"BloxOne Notification\\nType:{{.type}}\\nSubType:{{.subtype}}\\nTime:{{.occurred_time}}\\nSeverity:{{.severity}}\\nSubject:{{.short_subject}}\"\n}",
    }
    return manage_generic_subscription(webhook_template,integration,payload,True)

def subs_create_teams(integration,payload):
    print ("Provisioning Teams")

    webhook_template={
        "name": "Marketplace: BloxOne MS Teams notifications. Installed by: "+payload["creator"]+" id: "+payload['configuration']["subscriptionId"],
        "created_by": "Marketplace integration installed by: "+payload["creator"]+" subscription: "+payload['configuration']["subscriptionId"],
        "channel_type_id": "8d69f684-e70e-4ab1-9eae-39f034cf2045",
        "config": {
            "authentication": {"type": "None"},
            "url": payload['configuration']["webhook"]
        },
        "template": "{\n\t\"text\": \"BloxOne Notification\\nType:{{.type}}\\nSubType:{{.subtype}}\\nTime:{{.occurred_time}}\\nSeverity:{{.severity}}\\nSubject:{{.short_subject}}\"\n}",
    }
    return manage_generic_subscription(webhook_template,integration,payload,True)

def subs_create_telegram(integration,payload):
    print ("Provisioning Telegram")
    webhook_template={
        "name": "Marketplace: BloxOne Telegram notifications. Installed by: "+payload["creator"]+" id: "+payload['configuration']["subscriptionId"],
        "created_by": "Marketplace integration installed by: "+payload["creator"]+" subscription: "+payload['configuration']["subscriptionId"],
        "channel_type_id": "8d69f684-e70e-4ab1-9eae-39f034cf2045",
        "config": {
            "authentication": {"type": "None"},
            "url": "https://api.telegram.org/"+payload['configuration']["bot_id"]+"/sendMessage"
        },
        "template": "{\"chat_id\":"+payload['configuration']["chat_id"]+",\"parse_mode\":\"HTML\",\"disable_web_page_preview\":False,\n\t\"text\": \"BloxOne Notification\\nType:{{.type}}\\nSubType:{{.subtype}}\\nTime:{{.occurred_time}}\\nSeverity:{{.severity}}\\nSubject:{{.short_subject}}\"\n}",
    }
    return manage_generic_subscription(webhook_template,integration,payload,True)

def subs_cancel(integration,payload):
    print ("Canceling "+integration)
    return manage_generic_subscription('',integration,payload,False)

def subs_default(integration,payload):
    print ("Provisioning Default")
    return False

def provision_integration (action,integration,payload):
    ###The webhook handler should know where marketplace integrations scripts are located and execute the "init" with payload.
    exec_action = {
        'create_b1_slack':subs_create_slack,
        'create_b1_teams':subs_create_teams,
        'create_b1_telegram':subs_create_telegram,
        'cancel_b1_slack':subs_cancel,
        'cancel_b1_teams':subs_cancel,
        'cancel_b1_telegram':subs_cancel,
    }
    return exec_action.get(action+'_'+integration,subs_default)(integration,payload)


def lambda_handler(event, context):
    basic_auth_user_pwd=base64.b64decode(event['headers']['authorization'].split(" ")[1]).decode()
    #print (basic_auth_user_pwd)
    #
    if (basic_auth_user_pwd == os.environ['basic_http_auth']):
        eventUrl = event['queryStringParameters']['eventUrl']
        path=event['rawPath'].split("/")
        subscr_action=path[1]
        subscr_app=path[2]
        print (subscr_app, subscr_action, eventUrl)
        token = get_appdirect_token(os.environ['appdirect_key'],os.environ['appdirect_secret'])
        #print ("Token "+token)
        event=pull_appdirect_event(eventUrl,token)
        print (json.dumps(event))
        #store subscription id with APIKey in DynamoDB
        #new function to provision different application
        #payload/configuration creator/email
        status=provision_integration(subscr_action,subscr_app,{'creator':event['creator']['email'],'configuration':event['payload']['configuration']})
        #        slack_notification("Application: "+subscr_app+"\nAction: "+subscr_action+"\nEvent URL: "+eventUrl+"\nRequestor: "+event['creator']['email']+"\nConfiguration: "+json.dumps(event['payload']['configuration']))
        #check status
        webhook_response = {
            'statusCode': 200,
            'body': '{"success":true,"accountIdentifier":"'+secrets.token_urlsafe(16)+'","message":"Provisioned"}'
        }
    else:
        print("Bad credetials")
        webhook_response = {'statusCode': 401}

    return webhook_response