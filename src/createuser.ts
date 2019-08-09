import { DynamoDB } from 'aws-sdk';
import * as crypto from 'crypto';
import { resolve } from 'url';

const ddb = new DynamoDB.DocumentClient()
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


export const saveDbRecord = (DBrecord: JSON, DBtable: string, fn: any): any => {
  let err;
  try {
    console.log('Preparing to save data');
    const params = {
      TableName: DBtable,
      Item: DBrecord
    }
    
    const results = ddb.put(params).promise();
    return results;

  } catch (err) {
    console.log('error saving to db: ' + err);
    return err;
  }
}

export const computeHash = async (password: string, salt: crypto.BinaryLike, fn: any): Promise<any> => {
  let keylen = 128;
  let iterations = 4096;
  let digest = 'sha256';
  let err;

  if (!password) {
    console.log('no password provied to computeHash function');
    err = 'invalid password or no password found for hashing algorithm';
    return err;
  }

  if (salt == undefined) {
    const salter = await generateSalt(1024, function (err: string, buf: Buffer) {
      try {
        console.log("no salt provided - generating new salt...");
        console.log(`salt gen substring: ${buf.toString('base64').substring(0, 15)}`);
        crypto.pbkdf2(password, buf.toString('base64'), iterations, keylen, digest, fn);
    } catch (err) {
        console.log('crpto.pbkdf2Sync computeHash function failed to generate salt.');
        return err;
      }
    })
  } else
    try {
        crypto.pbkdf2(password, salt, iterations, keylen, digest, fn);
    } catch (err) {
        console.log('crpto.pbkdf2Sync hashing failed in function hash - crypto support possibly disabled');
        return err;
      }
        
    };

export const generateSalt = (keylen: number, fn: any): any => {
  console.log(`...generating ${keylen} random bytes`);
  try {
  crypto.randomBytes(keylen, fn);
  } catch (err) {
    console.log("error generating salt");
  }  
}

export const handler = async (event: any = {}): Promise<any> => {

  console.log("creating user...");
  let response: any;
  let record: any;

  let mask = 'xxxxxxxx';
  let maskedJSON = event.body;
  maskedJSON.password = mask;
  console.log("JSON: " + JSON.stringify(maskedJSON));

  let username = JSON.stringify(event.body.username);
  let rawpassword = JSON.stringify(event.body.password);
  let salt: any 

  record = await computeHash(rawpassword, salt, function (err: string, derivedKey: Buffer): JSON {
    console.log("generating hash");
    let hash = derivedKey.toString('base64');
    record = {
      "username": username,
      "hashrecord": {
        "hash": hash,
        "salt": salt
      }
    }
      
    console.log(`hash gen substring: ${hash.substring(0, 15)}`);
    return record;
  });
  
  response = {
      'statusCode': 200,
      'body': JSON.stringify(record)
  }
  console.log(`record is ${record}`);
  return response;
}

