import { Request, Response } from "express";
import { getRepository } from "typeorm";
import { validate } from "class-validator";
import { User } from "../entity/User";
import { checkUserRefreshToken, signUserAccessToken, signUserRefreshToken } from "../shared/JWTUtil";


class AuthController {
  static login = async (req: Request, res: Response) => {
    //Check if username and password are set
    let { username, password } = req.body;
    if (!(username && password)) {
      res.status(400).send();
    }

    //Get user from database
    const userRepository = getRepository(User);
    let user: User;
    try {
      user = await userRepository.findOneOrFail({ where: { username } });
    } catch (error) {
      res.status(401).send();
    }

    //Check if encrypted password match
    if (!user.checkIfUnencryptedPasswordIsValid(password)) {
      res.status(401).send();
      return;
    }

    try {
      const usertoken = await signUserAccessToken(user);
      const refreshToken = await signUserRefreshToken(user);
      res.send({usertoken, refreshToken});
    } catch (error) {
      res.status(500).send();
      console.log(error);
      return;
    }
  };

  static changePassword = async (req: Request, res: Response) => {
    const userId = res.locals.jwtPayload.id;

    const { oldPassword, newPassword } = req.body;
    if (!(oldPassword && newPassword)) {
      res.status(400).send();
    }

    const userRepository = getRepository(User);
    let user: User;
    try {
      user = await userRepository.findOne({ where: { id: userId }});
    } catch (id) {
      res.status(401).send();
    }

    if (!user.checkIfUnencryptedPasswordIsValid(oldPassword)) {
      res.status(401).send();
      return;
    }

    user.password = newPassword;
    const errors = await validate(user);
    if (errors.length > 0) {
      res.status(400).send(errors);
      return;
    }
    
    user.hashPassword();
    userRepository.save(user);

    res.status(204).send();
  };

  static refreshToken = async (req: Request, res: Response) => {
    let { refreshToken } = req.body;
    if(!refreshToken) {
      res.status(500).send("no token provided");
    }

    let payload;
    try {
      payload = await checkUserRefreshToken(refreshToken);
    } catch (error) {
      res.status(500).send(error.message);
      return;
    }
    
    //Get user from database
    const userRepository = getRepository(User);
    let user = await userRepository.find({
      where: { id: payload['id'] },
      select: ["id", "username", "role"]
    });
    
    try {
      const usertoken = await signUserAccessToken(user[0]);
      const refreshToken = await signUserRefreshToken(user[0]);
      res.send({usertoken, refreshToken});
    } catch (error) {
      res.status(401).send();
    }

  };
}
export default AuthController;