import { SetMetadata } from '@nestjs/common';

export const LOG_PERFORMANCE = 'log_performance';
export const LogPerformance = (operation?: string) => SetMetadata(LOG_PERFORMANCE, operation);
