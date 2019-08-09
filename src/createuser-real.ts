import { DynamoDB } from 'aws-sdk';
import * as crypto from 'crypto';
import { resolve } from 'url';

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

export const saveDbRecord = async (DBrecord: JSON, DBtable: string, fn: any): Promise<any> => {
  let err;
  try {
    console.log('Preparing to save data');
    const params = {
      TableName: DBtable,
      Item: DBrecord
    }
    
    const results = await ddb.put(params).promise();
    return results;

  } catch (err) {
    console.log('error saving to db: ' + err);
    return err;
  }
}

export const computeHash = (password: string, salt: crypto.BinaryLike, fn: any): any => {
  let keylen = 128;
  let iterations = 4096;
  let digest = 'sha256';
  let err;

  if (!password || !salt ) {
      if (!salt) {
        err = 'invalid salt or no salt found in hashing algorithm'
      } else if (!password) {
        err = 'invalid password or no password found for hashing algorithm'
      } else {
        err = 'invalid calilback or no callback found for hashing algorithm'
      }
      console.log("something went wrong.  Err:");
      console.log(err);
      // console.log("returnning error to function");
      try {
        return(err);  
      } catch {
        console.log('failure returning error to callback or no callback specified');
      }
  } else {
    try {
        crypto.pbkdf2(password, salt, iterations, keylen, digest, fn);
    } catch (err) {
        console.log('crpto.pbkdf2Sync hashing failed in function hash - crypto support possibly disabled');
        return err;
      }
        
    };
  }

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
  let results: any;
  let record: any;
  let salt: string;
  let hashpassword: string;
  let username: string;
  let rawpassword: string;
  let hash: any;

  if (!event.body) {
    console.log("failed event.body");
    if (!event.pathParameters.username) {
      console.log("Error: no path parameters")
      response = {
        headers: { 'Access-Control-Allow-Origin': '*' },
        statusCode: 406,
      }
      return response;
    } else {
      console.log("event.body present")
      console.log(JSON.stringify(event));
      username = event.pathParameters.username;
      console.log("username: " + username);
    }
  
  } else {
    console.log("processing JSON payload");
    // console.log("JSON: " + JSON.stringify(event.body));
    // masking out plain text password
    let mask = 'xxxxxxxxx'
    let maskedJSON = event.body
    maskedJSON.password = mask
    console.log("JSON: " + JSON.stringify(maskedJSON));

    username = JSON.stringify(event.body.username);
    rawpassword = JSON.stringify(event.body.password);

    const salter: any = await generateSalt(1024, async function (err: string, buf: Buffer) {
      salt = buf.toString('base64');
      const hasher = await computeHash(rawpassword, salt, async function (err: string, derivedKey: Buffer) {
        console.log("generating hash");
        hash = derivedKey.toString('base64');
        record = {
          "username": username,
          "hashrecord": {
            "hash": hash,
            "salt": salt
          }
        }
        await saveDbRecord(record, 'AuthTable', async function (err: string, DBresults: any) {
          console.log("saving to db...");
          console.log(JSON.stringify(record));
          console.log("save to DB operation complete.")
          response = {
            'statusCode': 200,
            'body': JSON.stringify(record)
          }
          return response;
        });
      });
    });

    

    
    /*
    const generateNewSalt = new Promise((resolve, reject) => {
      // setTimeout(() => { reject(new Error("failed to generate salt.")) }, 2000);
      console.log("generating salt:");
      generateSalt(1024, function (err: string, buf: Buffer) {
        salt = buf.toString('base64');
        console.log(`${buf.length} bytes of random data`);
        if (err) {
          console.log('rejected salt generation');
          reject(err);
        }
        else {
          console.log('completed salt generation...resolving');
          resolve(salt);
        };
      });
    });
    generateNewSalt.then(
      result => {
        const generateNewHash = new Promise((resolve, reject) => {
          hash = computeHash(rawpassword, salt, function (err: string, derivedKey: Buffer) {
            console.log('generating hash');
            if (err) {
              throw err;
            } else {
              console.log("derivedKey is...")
              //this is the resultant hash
              console.log(derivedKey.toString('hex'));
              resolve(hash);
            }
          }
          );
        });
              
        generateNewHash.then(
          result => {
            console.log(`hash is... ${hash}`)
            try {
              hashpassword = hash.toString
              console.log(`generated hash as ${hashpassword} for userId ${username}`);
              console.log("building record: " + record);
              record = {
                "username": username,
                "hashrecord": {
                  "hash": hashpassword,
                  "salt": salt
                }
              }
            } catch (err) {
              console.log(`caught error ${err}`);
                console.log('hell with this, will this work? #justfakeit');
                record = {
                  "username": username,
                  "hash": {
                    "rawhash": 'Thisisafakehashedpassword',
                    "salt": salt
                  }
                }
            };
            const saveToDatabase = new Promise((resolve, reject) => {
              // setTimeout(() => { reject(new Error("failed to generate hash.")) }, 2000);
              saveDbRecord(record, 'AuthTable', function (err: string, DBresults: any) {
                console.log("saving to db...");
                if (err) {
                  reject(err);
                } else {
                  resolve(DBresults);
                }
              });
            });
            saveToDatabase.then(
              result => {
                console.log("save to DB operation complete.")
                response = {
                  'statusCode': 200,
                  'body': JSON.stringify(record)
                }
                return response;
              },
              error => {
                console.log("failed to save record to DyanmoDb");
                response = {
                  headers: { 'Access-Control-Allow-Origin': '*' },
                  body: error,
                  statusCode: 300,
                  }
                return response;
              }
            );
          },
          
          error => {
            console.log("failed to save record to DyanmoDb");
            response = {
              headers: { 'Access-Control-Allow-Origin': '*' },
              body: error,
              statusCode: 301,
            }
            return response;
          }
        );
      },
      error => {
        console.log("request generateSalt() timed out during operation")
          response = {
            headers: { 'Access-Control-Allow-Origin': '*' },
            body: error,
            statusCode: 501,
          }
        return response;
      }
    ); */
    }
}
