namespace WebApplication4
{
    using System;
    using System.Threading.Tasks;

    namespace WebApplication4.Services
    {
        public class RequestQueueService
        {
            private readonly SemaphoreSlim _semaphore = new(1, 1);
            private readonly TimeSpan _cooldown = TimeSpan.FromSeconds(5);

            public async Task<T> Enqueue<T>(Func<Task<T>> action)
            {
                // Если семафор занят (уже выполняется запрос) — отклоняем новый
                if (!_semaphore.Wait(0))
                {
                    throw new Exception("Сервер занят. Попробуйте позже.");
                }

                try
                {
                    var result = await action();
                    await Task.Delay(_cooldown); // Задержка перед следующим запросом
                    return result;
                }
                finally
                {
                    _semaphore.Release();
                }
            }
        }
    }

}
