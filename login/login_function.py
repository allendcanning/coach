import json
import os, time
import boto3
import hmac
import hashlib
import base64
import time
from jose import jwk, jwt
from jose.utils import base64url_decode
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from botocore.vendored import requests
from urllib.parse import unquote_plus
from urllib.request import urlopen

# Set timezone
os.environ['TZ'] = 'US/Eastern'
time.tzset()

table_name = "user_info"

# Open DB connection
dynamodb = boto3.resource('dynamodb')

# Connect to dynamo db table
t = dynamodb.Table(table_name)

def log_error(msg):
  print(msg)

def get_config_data(environment):
  client = boto3.client('ssm')
  config = {}

  ssmpath="/a2c/"+environment+"/s3_html_bucket"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['s3_html_bucket'] = response['Parameter']['Value']
  
  ssmpath="/a2c/"+environment+"/cognito_pool"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_pool'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/cognito_client_id"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_client_id'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/cognito_client_secret_hash"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_client_secret_hash'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/content_url"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['content_url'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/coach_url"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['coach_url'] =response['Parameter']['Value'] 

  return config

def validate_token(config,token):
  region = 'us-east-1'
  user_record = {}
  keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, config['cognito_pool'])
  response = urlopen(keys_url)
  keys = json.loads(response.read())['keys']

  headers = jwt.get_unverified_headers(token)
  kid = headers['kid']
  # search for the kid in the downloaded public keys
  key_index = -1
  for i in range(len(keys)):
      if kid == keys[i]['kid']:
          key_index = i
          break
  if key_index == -1:
      log_error('Public key not found in jwks.json')
      return False

  # construct the public key
  public_key = jwk.construct(keys[key_index])

  # get the last two sections of the token,
  # message and signature (encoded in base64)
  message, encoded_signature = str(token).rsplit('.', 1)

  # decode the signature
  decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

  # verify the signature
  if not public_key.verify(message.encode("utf8"), decoded_signature):
      log_error('Signature verification failed')
      return 'False'

  # since we passed the verification, we can now safely
  # use the unverified claims
  claims = jwt.get_unverified_claims(token)

  log_error('Token claims = '+json.dumps(claims))

  # additionally we can verify the token expiration
  if time.time() > claims['exp']:
      log_error('Token is expired')
      return 'False'

  if claims['aud'] != config['cognito_client_id']:
      log_error('Token claims not valid for this application')
      return 'False'
  
  user_record['username'] = claims['cognito:username']
  user_record['token'] = token

  return user_record

def authenticate_user(config,authparams):
  # Get cognito handle
  cognito = boto3.client('cognito-idp')

  message = authparams['USERNAME'] + config['cognito_client_id']
  dig = hmac.new(key=bytes(config['cognito_client_secret_hash'],'UTF-8'),msg=message.encode('UTF-8'),digestmod=hashlib.sha256).digest()

  authparams['SECRET_HASH'] = base64.b64encode(dig).decode()

  log_error('Auth record = '+json.dumps(authparams))

  # Initiate Authentication
  try:
    response = cognito.admin_initiate_auth(UserPoolId=config['cognito_pool'],
                                 ClientId=config['cognito_client_id'],
                                 AuthFlow='ADMIN_NO_SRP_AUTH',
                                 AuthParameters=authparams)
    log_error(json.dumps(response))
  except ClientError as e:
    log_error('Admin Initiate Auth failed: '+e.response['Error']['Message'])
    return 'False'

  return response['AuthenticationResult']['IdToken']

def print_form():
  content = '<form method="post" action="">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += 'Enter Password: <input type="password" name="password"><p>\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

  return content

def set_portal_data(config,token,record):
  headers = { 'Authorization': token }

  data = ""
  for item in record:
    data += item+'='+record[item]+'&'

  data = data.rstrip('&')

  r = requests.post(config['content_url'],headers=headers,data=data)

  body = r.text

  return body

def get_account_type(environment,username):
  user_record = {}

  log_error("Checking for user "+username)
  try:
    item = t.get_item(
      Key={ 'username': username
          }
      )
    log_error("Item = "+json.dumps(item))
    user_record = item['Item']
    log_error("Item = "+json.dumps(user_record))
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])

  if 'username' not in user_record:
    return False
  else:
    return user_record['account_type']

def get_coach_view(config,token,athlete):
  headers = { 'Authorization': token }

  payload = { 'athlete': athlete }

  r = requests.get(config['coach_url'],headers=headers,params=payload)

  body = r.text

  return body

def get_portal_data(config,token,action):
  headers = { 'Authorization': token }

  if action != False:
    log_error("Calling POST with "+action)
    data = "action="+action
    r = requests.post(config['content_url'],headers=headers,data=data)
  else:
    log_error("Calling GET")
    r = requests.get(config['content_url'],headers=headers)

  body = r.text

  return body

def lambda_handler(event, context):
  token = 'False'
  record = {}
  athlete = False
  username = ""
  action = "display"

  log_error("Event = "+json.dumps(event))

  # Get the environment from the context stage
  environment = event['requestContext']['stage']
  # look up the config data using environment
  config = get_config_data(environment)
  
  # Build HTML content
  css = '<link rel="stylesheet" href="https://s3.amazonaws.com/'+config['s3_html_bucket']+'/css/a2c.css" type="text/css" />'
  content = "<html><head><title>A2C Portal</title>\n"
  content += css+'</head>'
  content += "<body><h3>A2C Portal</h3>"

  # Get jwt token
  if 'headers' in event:
    if event['headers'] != None:
      if 'cookie' in event['headers']:
        cookie = event['headers']['cookie']
        token = cookie.split('=')[1]
        log_error('Got Token = '+token)
        if token != 'False':
          auth_record = validate_token(config,token)
          if auth_record != 'False':
            token = auth_record['token']
            username = auth_record['username']
          else:
            token = 'False'
          
  if 'queryStringParameters' in event:
    if event['queryStringParameters'] != None:
      if 'athlete' in event['queryStringParameters']:
        athlete = event['queryStringParameters']['athlete']

  if 'body' in event:
    if event['body'] != None:
      # Parse the post parameters
      postparams = event['body']
      auth = {}
      if '&' in postparams:
        log_error('Parsing post params')
        for params in postparams.split('&'):
          key = params.split('=')[0]
          value = params.split('=')[1]
          if key == "Submit":
            continue
          if key == "username":
            auth['USERNAME'] = unquote_plus(value)
          elif key == "password":
            auth['PASSWORD'] = unquote_plus(value)
          else: 
            record[key] = unquote_plus(value)
      else:
        log_error('Parsing single post param: '+postparams)
        key = postparams.split('=')[0]
        value = postparams.split('=')[1]
        record[key] = value
        
      if 'USERNAME' in auth:
        token = authenticate_user(config,auth)
        username = auth['USERNAME']
        
      if 'action' in record:
        action = record['action']

      log_error('Got token = '+token)
      if token != 'False':
        if action == 'Process':
          log_error("Setting portal data")
          content += set_portal_data(config,token,record)
        else:
          log_error("Getting portal data")
          content += get_portal_data(config,token,action)
      else:
        content += print_form()
    else:
      # there are no post parameters
      if token != 'False':
         content += get_portal_data(config,token,action)
      else:
        content += print_form()
  else:
    if token != 'False':
      content += get_portal_data(config,token,action) 
    else:
      content += print_form()

  content += "</body></html>"

  cookie = 'Token='+str(token)
  return { 'statusCode': 200,
           'headers': {
              'Content-type': 'text/html',
              'Set-Cookie': cookie
           },
           'body': content
         }