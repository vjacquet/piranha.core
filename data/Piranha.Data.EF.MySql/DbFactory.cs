#if DEBUG
/*
 * Copyright (c) 2020 Håkan Edling
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * http://github.com/piranhacms/piranha.core
 *
 */

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;

namespace Piranha.Data.EF.MySql
{
    /// <summary>
    /// Factory for creating a db context. Only used in dev mode
    /// when creating migrations.
    /// </summary>
    [NoCoverage]
    public class DbFactory : IDesignTimeDbContextFactory<MySqlDb>
    {
        /// <summary>
        /// Creates a new db context.
        /// </summary>
        /// <param name="args">The arguments</param>
        /// <returns>The db context</returns>
        public MySqlDb CreateDbContext(string[] args)
        {
            var builder = new DbContextOptionsBuilder<MySqlDb>();
            builder.UseMySql("Server=localhost;Port=8889;Database=piranha;User=root;Password=root;");
            return new MySqlDb(builder.Options);
        }
    }
}
#endif