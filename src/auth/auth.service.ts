import { Body, ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from 'argon2';
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtModule, JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{
    constructor(private prisma: PrismaService, private jwt:JwtService,private config:ConfigService){}
    
    
    async singup(dto: AuthDto)
    {
        
        //generate our hash for the password
        const hash = await argon.hash(dto.password);

        //save the user in the DB
        try
        {
            const user = await this.prisma.user.create({
                data: {
                    email:dto.email,
                    hash,
                },
            });

            //return the saved user

            return this.signToken(user.id,user.email);
        }
        catch(error){
           if(error instanceof PrismaClientKnownRequestError){
            if(error.code==='P2002')
            {
                throw new ForbiddenException('User already exsist')
            }
           } 
        }

    }

    async singin (dto: AuthDto)
    {
        //Find the user by email

        const user = await this.prisma.user.findFirst({
            where: {
                email:dto.email,
            },
        });

        // If user doesnt exist throw exception
        if(!user)
        {
            throw new ForbiddenException(
                'User not found',
            );
        }

        

        // comapre password


        const pwMatches = await argon.verify(
            user.hash,
            dto.password,
        );
        // Password mismatch throw exception


        if(!pwMatches)
        {
            throw new ForbiddenException(
                'Password incorrect',
            )
        }
        //send back the user
        
        return this.signToken(user.id,user.email);
    }

    async signToken(userId:number, email:string):Promise<{access_token:string}>{
        const payload = {
            sub: userId,
            email,
        };
        const secret = this.config.get('JWT_SECRET');

        const token =  await this.jwt.signAsync(payload,{
            expiresIn:'10m',
            secret:secret,
        })

        return {
            access_token : token,
        }

    }
}