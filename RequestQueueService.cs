namespace WebApplication4
{
    // Services/RequestQueueService.cs
    using System;
    using System.Threading;
    using System.Threading.Tasks;

    public class RequestQueueService
    {
        private readonly SemaphoreSlim _semaphore = new(1); // Только один запрос за раз
        private readonly TimeSpan _delayBetweenRequests = TimeSpan.FromSeconds(3); // Задержка между запросами

        public async Task<T> Enqueue<T>(Func<Task<T>> func)
        {
            await _semaphore.WaitAsync(); // Ждём свою очередь

            try
            {
                var result = await func();             // Выполняем запрос
                await Task.Delay(_delayBetweenRequests); // Задержка между запросами
                return result;
            }
            finally
            {
                _semaphore.Release(); // Освобождаем очередь
            }
        }
    }

}
