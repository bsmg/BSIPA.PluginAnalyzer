using DryIoc;
using Hive.Plugins;

namespace BSIPA.PluginAnalyzer;
#pragma warning disable CA1052

[PluginStartup]
public class Startup
{
    public static void ConfigureContainer(Container container)
    {
        container.RegisterMany<PluginAnalyzerPlugin>();
    }
}