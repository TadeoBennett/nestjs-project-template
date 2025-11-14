import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import helmet from 'helmet';
// import { doubleCsrf } from 'csrf-csrf';
// import * as session from 'express-session';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // // CSRF
  // const {
  //   doubleCsrfProtection, // This is the default CSRF protection middleware.
  // } = doubleCsrf(doubleCsrfOptions);
  // app.use(doubleCsrfProtection);
  // app.use(
  //   session({
  //     secret: process.env.SESSION_SECRET || 'keyboard cat',
  //     resave: false,
  //     saveUninitialized: false,
  //     cookie: { secure: process.env.NODE_ENV === 'production' },
  //   }),
  // );

  // CORS
  const allowedOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',')
    : ['http://localhost:3000'];

  app.enableCors({
    origin: allowedOrigins,
    // fallback provided just in case as a comma separated list
    methods: process.env.CORS_METHODS ?? 'GET,PUT,PATCH,POST,DELETE',
    allowedHeaders: process.env.CORS_HEADERS
      ? process.env.CORS_HEADERS.split(',')
      : ['Content-Type', 'Authorization'],
    credentials: process.env.CORS_CREDENTIALS === 'true', // convert string to boolean
    maxAge: process.env.CORS_MAX_AGE
      ? parseInt(process.env.CORS_MAX_AGE)
      : 3600,
  });

  // HELMET
  app.use(helmet());

  // VALIDATION WITH DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      // disableErrorMessages: true,
      whitelist: true,
      // transform: true,
      stopAtFirstError: true,
    }),
  );
  app.setGlobalPrefix('api');
  await app.listen(process.env.PORT ?? 3000);
}
void bootstrap();
