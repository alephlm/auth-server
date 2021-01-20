import { config } from "dotenv"
config()
export default {
 privateKey: process.env.PRIVATE_KEY,
 publicKey: process.env.PUBLIC_KEY,
 refreshTokenSecret: process.env.REFRESH_KEY
}