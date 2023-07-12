using System.Text.Json.Serialization;
using Hive.Converters;
using Version = Hive.Versioning.Version;

namespace BSIPA.PluginAnalyzer;

public class BSIPAManifest
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("version"), JsonConverter(typeof(VersionJsonConverter))]
    public Version Version { get; set; } = Version.Zero;
    
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
    
    [JsonPropertyName("dependsOn")]
    public Dictionary<string, string> Dependencies { get; set; } = new();
    
    [JsonPropertyName("conflictsWith")]
    public Dictionary<string, string> ConflictsWith { get; set; } = new();
}