using System.Text.Json;
using System.Text.Json.Serialization;
using Hive.Converters;
using Version = Hive.Versioning.Version;

namespace BSIPA.PluginAnalyzer;

#pragma warning disable CA2227
public class BSIPAManifest
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
    
    [JsonPropertyName("author")]
    public string Author { get; set; } = string.Empty;

    [JsonPropertyName("version"), JsonConverter(typeof(VersionJsonConverter))]
    public Version Version { get; set; } = Version.Zero;
    
    [JsonPropertyName("dependsOn")]
    // ReSharper disable once CollectionNeverUpdated.Global
    public Dictionary<string, string> Dependencies { get; set; } = new();
    
    [JsonPropertyName("conflictsWith")]
    // ReSharper disable once CollectionNeverUpdated.Global
    public Dictionary<string, string> ConflictsWith { get; set; } = new();

    [JsonExtensionData]
    // ReSharper disable once CollectionNeverUpdated.Global
    public Dictionary<string, JsonElement> ExtensionData { get; set; } = new();
}