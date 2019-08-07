import { DynamoDB } from 'aws-sdk';
import * as crypto from 'crypto';

/**
 *
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Context doc: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html 
 * @param {Object} context
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 * 
 */

const ddb = new DynamoDB.DocumentClient()
// const ses = new SES()

export const computeHash = (password: string, salt: crypto.BinaryLike, fn: any): any => {
  let keylen = 128;
  let iterations = 4096;
  let digest = 'sha256';
  let err;

    if (!password || !salt || !fn) {
      if (!salt) {
        err = 'invalid salt or no salt found in hashing algorithm'
      } else if (!password) {
        err = 'invalid password or no password found for hashing algorithm'
      } else {
        err = 'invalid calilback or no callback found for hashing algorithm'
      }
      console.log(err);
      try {
        fn(err);  
      } catch {
        console.log('failure returning error to callback or no callback specified');
      }
      } else {
      try {
        crypto.pbkdf2(password, salt, iterations, keylen, digest, fn);
      } catch (err) {
        console.log('crpto.pbkdf2 hashing failed in function hash - crypto support possibly disabled');
        return fn(err);
      }
        
  };
}

export const generateSalt = (keylen: number, fn: any): any => {
  try {
  crypto.randomBytes(keylen, fn);
  } catch (err) {
    console.log("error generating salt");
  }  
  }

export const handler = async (event: any = {}): Promise<any> => {

  console.log("creating user...");
  let response, record;
  let salt: string;
  let hashpassword: string;
  let username: string;
  let rawpassword: string;

  if (!event.body) {
    if (!event.pathParameters.username) {
      console.log("Error: no path parameters")
      response = {
        headers: { 'Access-Control-Allow-Origin': '*' },
        statusCode: 406,
      }
      return response;
    } else {
      username = event.pathParameters.username;
      console.log("username: " + username);
    }
  
  } else {
    console.log("processing JSON payload");
    console.log("JSON: " + JSON.stringify(event.body));
    let data = JSON.parse(event.body);
    username = data.username;
    rawpassword = data.password;
    generateSalt(1024, function (err: string, buf: Buffer) {
      if (err) throw err;
      salt = buf.toString('base64');
      console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);
      computeHash(rawpassword, salt, async function (err: string, hash: any) {
        if (err) {
          console.log('Error in hash: ' + err);
        } else {
          hashpassword = hash.toString
          console.log(`generated hash as ${hashpassword} for userId ${username}`)

          record = {
            "username": username,
            "hashrecord": {
              "hash": hashpassword,
              "salt": salt
            }
          };

          console.log("building record: " + record);
          try {
            console.log('Preparing to save data');
            const params = {
              TableName: 'AuthTable',
              Item: record
            }
            
            const results = await ddb.put(params).promise();
      
            if (!results) {
              console.log('No results found')
              response = {
                headers: { 'Access-Control-Allow-Origin': '*' },
                statusCode: 400,
              }
            } else {
              console.log("results not 400 error")
              response = {
                'statusCode': 200,
                'body': JSON.stringify(record)
              }
            }
          } catch (err) {
            response = {
              headers: { 'Access-Control-Allow-Origin': '*' },
              body: err,
              statusCode: 500
            }
            console.log(err)
            // return err
          }
          return response;  

        }
      });
    });
  }
}
