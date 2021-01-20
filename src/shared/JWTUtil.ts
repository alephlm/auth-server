import * as jwt from "jsonwebtoken";
import { User } from "../entity/User";
import config from "../config/config"
import { RedisClient } from "redis";
import { InternalServerError, Unauthorized } from "http-errors";

let client = new RedisClient({});

client.on("error", function (error) {
  console.error(error);
});

interface TokenConfig {
  timeToExpire?: '1m' | '10m' | '30m' | '1h' | '1d' | '30d' | '1y';
  algorithm: 'RS256' | 'HS256';
  key: string;
  token?: string
}

const signUserAccessToken = (user: User): Promise<string> => {
  let token: TokenConfig = {
    algorithm: "RS256",
    timeToExpire: "1m",
    key: config.privateKey
  };
  return generateUserToken(user, token);
};

const signUserRefreshToken = (user: User): Promise<string> => {
  let token: TokenConfig = {
    algorithm: "HS256",
    timeToExpire: "1y",
    key: config.refreshTokenSecret
  };
  return generateUserToken(user, token, true);
};

const checkUserAccessToken = (userToken: string): Promise<string | object> => {
  let tokenConfig: TokenConfig = {
    algorithm: "RS256",
    token: userToken,
    key: config.publicKey
  };
  return checkUserToken(tokenConfig);
};

const checkUserRefreshToken = (userToken: string): Promise<string | object> => {
  let token: TokenConfig = {
    algorithm: "HS256",
    token: userToken,
    key: config.refreshTokenSecret
  };
  return checkUserToken(token, true);
};

const generateUserToken = (user: User, config: TokenConfig, updateUserRedisToken = false): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      const payload = { id: user.id, name: user.username, role: user.role }
      jwt.sign(payload, config.key, { expiresIn: config.timeToExpire, algorithm: config.algorithm }, (err, token) => {
        if (err) {
          console.log(err);
          reject(new InternalServerError())
          return;
        }
        if (updateUserRedisToken) {
          client.set(payload.id.toString(), token);
        }
        resolve(token);
      });
    } catch (error) {
      console.log(error);
      reject(error);
    }
  });
}

const checkUserToken = (config: TokenConfig, checkRedis = false): Promise<string | object> => {
  return new Promise((resolve, reject) => {
    try {
      jwt.verify(config.token, config.key, { algorithms: [config.algorithm] }, (err, response) => {
        if (err) {
          reject(err);
          return;
        }
        if (checkRedis) {
          client.get(response['id'], (err, result) => {
            if (err) {
              console.log(err.message);
              reject(new InternalServerError());
              return;
            }
            if (config.token == result) {
              return resolve(response);
            } else {
              reject(new Unauthorized());
              return;
            }
          })
        } else {
          return resolve(response);
        }
      });
    } catch (error) {
      console.log(error);
      reject(error);
    }
  });
}

export { signUserAccessToken, checkUserAccessToken, checkUserRefreshToken, signUserRefreshToken };
