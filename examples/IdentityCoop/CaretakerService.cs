using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Piranha;
using Piranha.AspNetCore.Identity;
using Piranha.AttributeBuilder;

namespace IdentityCoop
{
    public class CaretakerService : IHostedService
    {
        private readonly IServiceScopeFactory _serviceScopeFactory;

        public CaretakerService(IServiceScopeFactory serviceScopeFactory)
        {
            _serviceScopeFactory = serviceScopeFactory;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using (var scope = _serviceScopeFactory.CreateScope())
            {
                var api = scope.ServiceProvider.GetRequiredService<IApi>();
                App.Init(api);

                var seed = scope.ServiceProvider.GetService<IIdentitySeed>();
                if (seed != null)
                {
                    await seed.CreateAsync();
                }

                // Build content types
                new ContentTypeBuilder(api)
                    .AddAssembly(typeof(Startup).Assembly)
                    .Build()
                    .DeleteOrphans();

                await Seed.RunAsync(api);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
