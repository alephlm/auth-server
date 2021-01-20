import { Request, Response, NextFunction } from "express";
import { checkUserAccessToken } from "../shared/JWTUtil";

export const checkJwt = async (req: Request, res: Response, next: NextFunction) => {
  //Get the jwt token from the head
  const token = <string>req.headers["auth"];
  let jwtPayload;
  
  //Try to validate the token and get data
  try {
    jwtPayload = await checkUserAccessToken(token);
    res.locals.jwtPayload = jwtPayload;
  } catch (error) {
    
    console.log(error);
    //If token is not valid, respond with 401 (unauthorized)
    res.status(401).send(error.message);
    return;
  }
  next();
};