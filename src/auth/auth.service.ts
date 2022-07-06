
import { ForbiddenException, Injectable, Req } from "@nestjs/common"
import { PrismaService } from "../prisma/prisma.service"
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) { }

  async signup(dto: AuthDto) {

    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        }
      });

      return this.signToken(user.id, user.email);

    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === "P2002") {
          throw new ForbiddenException("Email already exists");
        }

      }
    }
  }

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      }
    })

    if (!user) throw new ForbiddenException("Invalid credentials - no user found with that email")

    const pwMatches = await argon.verify(user.hash, dto.password);

    if (!pwMatches) throw new ForbiddenException("Invalid credentials - password does not match");

    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    }

    const secret = this.configService.get('JWT_SECRET');

    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '15min',
      secret: secret,
    });

    return {
      access_token: token,
    }

  }
}
