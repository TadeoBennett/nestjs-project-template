import { SetMetadata } from '@nestjs/common';

//now we just call @Public on routes where we need to remove JWT authentication
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
