import json
import os, time
import re
import hmac
import hashlib
import base64
import boto3
from jose import jwk, jwt
from jose.utils import base64url_decode
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import urllib.parse
from urllib.request import urlopen

# Set timezone
os.environ['TZ'] = 'US/Eastern'
time.tzset()

# Open DB connection
dynamodb = boto3.resource('dynamodb')

# This information needs to move to paramater store
table_name = "user_info"

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

def get_student_data(athlete):
  user_record = {}

  username = base64.urlsafe_b64decode(athlete).decode('UTF-8')

  log_error("Checking for user "+username)
  try:
    item = t.get_item(
      Key={ 'username': username
          }
      )
    user_record = item['Item']
    log_error("Item = "+json.dumps(user_record))
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])

  if 'username' not in user_record:
    user_record['username'] = username

  return user_record

def display_student_info(record):
  user_record = '<tr><td>\n'
  user_record += '  <table class="defTable">\n'
  user_record += '    <tr><th class="areaHead">Personal Information:</th></tr>\n'

  user_record += '    <tr><td class="header">Name: </td><td class="data">'
  if 'firstname' in record:
    user_record += record['firstname']+' '
  else:
    user_record += '&nbsp; '
  if 'lastname' in record:
    user_record += record['lastname']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Email: </td><td class="data">'
  if 'email' in record:
    user_record += record['email']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'
   
  user_record += '    <tr><td class="header">Phone: </td><td class="data">'
  if 'phone' in record:
    user_record += record['phone']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Address: </td><td class="data">'
  if 'address' in record:
    user_record += record['address']+', '
  else:
    user_record += '&nbsp;, '
  if 'city' in record:
    user_record += record['city']+' '
  else:
    user_record += '&nbsp; '
  if 'st' in record:
    user_record += record['st']+' '
  else:
    user_record += '&nbsp; '
  if 'zip' in record:
    user_record += record['zip']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Date of Birth: </td><td class="data">'
  if 'dob' in record:
    user_record += record['dob']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Parents: </td><td class="data">'
  if 'parents' in record:
    user_record += record['parents']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Parents Email: </td><td class="data">'
  if 'parentsemail' in record:
    user_record += record['parentsemail']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Parents Phone: </td><td class="data">'
  if 'parentsphone' in record:
    user_record += record['parentsphone']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'
  user_record += '  </table>\n'
  user_record += '</td>\n'
  
  user_record += '<td class="right">\n'
  user_record += '  <table class="defTable">\n'
  user_record += '    <tr><th class="areaHead">Academic Information:</th></tr>\n'

  user_record += '    <tr><td class="header">GPA: </td><td class="data">'
  if 'gpa' in record:
    user_record += record['gpa']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Rank: </td><td class="data">'
  if 'classrank' in record:
    user_record += record['classrank']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">YOG: </td><td class="data">'
  if 'yog' in record:
    user_record += record['yog']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">ACT: </td><td class="data">'
  if 'act' in record:
    if record['act'] != None:
      user_record += record['act']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">SAT: </td><td class="data">'
  if 'satw' in record:
    if 'satm' in record:
      user_record += str(int(record['satw'])+int(record['satm']))
      user_record += ' (M: '+record['satm']+'; W: '+record['satw']+')'
  else:
    user_record += 'N/A (M: N/A; W: N/A)'
  user_record += '    </td></tr>\n'
  user_record += '  </table>\n'
  user_record += '</td></tr>\n'

  user_record += '<tr><td colspan="2">\n'
  user_record += '  <table class="defTable">\n'
  user_record += '    <tr><th class="areaHead">Athletic Information:</th></tr>\n'

  user_record += '    <tr><td class="header">Sport: </td><td class="data">'
  if 'sport' in record:
    user_record += record['sport']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Position: </td><td class="data">'
  if 'pos' in record:
    user_record += record['pos']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Strong hand: </td><td class="data">'
  if 'stronghand' in record:
    user_record += record['stronghand']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Height: </td><td class="data">'
  if 'height' in record:
    user_record += record['height']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Weight: </td><td class="data">'
  if 'weight' in record:
    user_record += record['weight']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Other sports: </td><td class="data">'
  if 'othersports' in record:
    user_record += record['othersports']
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Athletic Statistics: </td><td class="data">'
  if 'athleticstats' in record:
    user_record += record['athleticstats'].replace('\n', '<br>')
  else:
    user_record += '&nbsp;'
  user_record += '    </td></tr>\n'

  user_record += '    <tr><td class="header">Highlight Links: </td><td class="data">'
  if 'highlights' in record:
    highlights = record['highlights']
    highlights = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', highlights)
    for h in highlights:
      user_record += '<a href="'+h+'">'+h+'</a><br>'
  else:
   user_record += '&nbsp;'
  user_record += '</td></tr>\n'
  user_record += '  </table>\n'
  user_record += '</td></tr>\n'

  return user_record

def start_html(config):
  # Build HTML content
  css = '<link rel="stylesheet" href="https://s3.amazonaws.com/'+config['s3_html_bucket']+'/css/a2c.css" type="text/css" />'
  content = "<html><head><title>A2C Portal</title>\n"
  content += css+'</head>'
  content += "<body><h3>A2C Portal</h3>"

  return content

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

def check_token(config,event):
  token = 'False'
  auth_record = {}
  auth_record['token'] = 'False'
  auth_record['username'] = 'False'

  # Get jwt token
  if 'headers' in event:
    if event['headers'] != None:
      if 'cookie' in event['headers']:
        cookie = event['headers']['cookie']
        cookie_name = cookie.split('=')[0]
        if cookie_name == 'Token':
          token = cookie.split('=')[1]
          log_error('Got Token = '+token)
          if token != 'False':
            auth_record = validate_token(config,token)

  return auth_record

def print_form(athlete):
  content = '<form method="post" action="">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += 'Enter Password: <input type="password" name="password"><p>\n'
  content += '<input type="hidden" name="athlete" value="+athlete+">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

  return content

def lambda_handler(event, context):
  token = False
  user_record = {}
  user_record['action'] = "Form"
  athlete = False

  # Log the event object
  log_error("Event = "+json.dumps(event))

  # Get the environment from the context stage
  environment = "dev"

  # look up the config data using environment
  config = get_config_data(environment)
  
  content = start_html(config)

  auth_record = check_token(config,event)

  if auth_record['token'] == 'False':
    # Check to see if they submitted the login form
    if 'body' in event:
      if event['body'] != None:
        # Parse the post parameters
        postparams = event['body']
        postparams = base64.b64decode(bytes(postparams,'UTF-8')).decode('utf-8')
        log_error('Got post params = '+postparams)
        auth = {}
        log_error('Parsing login form')
        params = urllib.parse.parse_qs(postparams)
        log_error("Params = "+str(params))
        if 'username' in params:
          log_error("Got username = "+params['username'][0])
          auth['USERNAME'] = params['username'][0]
        if 'password' in params:
          log_error("Got password = "+params['password'][0])
          auth['PASSWORD'] = params['password'][0]
        if 'athlete' in params:
          log_error("Got athlete = "+params['athlete'][0])
          athlete = params['athlete'][0]

        if 'USERNAME' in auth:
          token = authenticate_user(config,auth)
          username = auth['USERNAME']

          # Get user data
          if username != False:
            if athlete != False:
              athlete = base64.b64decode(bytes(athlete,'UTF-8')).decode('utf-8')
              athlete_record = get_student_data(athlete)
              log_error("Record = "+json.dumps(athlete_record))
              content += '<table class="topTable">\n'
              content += display_student_info(athlete_record)
              # End of table body and table
              content += "</table>\n"
          else:
            content += print_form(athlete)
  else:
    token = auth_record['token']

    if 'queryStringParameters' in event:
      if event['queryStringParameters'] != None:
        if 'athlete' in event['queryStringParameters']:
          athlete = event['queryStringParameters']['athlete']

          log_error("Got athlete = "+athlete)
          athlete_record = get_student_data(athlete)
          log_error("Record = "+json.dumps(athlete_record))
          content += '<table class="topTable">\n'
          content += display_student_info(athlete_record)
          # End of table body and table
          content += "</table>\n"

  content += "</body></html>"

  cookie = 'Token='+str(token)
  return { 'statusCode': 200,
           'headers': {
              'Content-type': 'text/html',
              'Set-Cookie': cookie
           },
           'body': content
         }
