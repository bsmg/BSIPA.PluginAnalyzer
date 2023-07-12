using System.Diagnostics;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using Hive.Controllers;
using Hive.Models;
using Hive.Versioning;
using Serilog;

namespace BSIPA.PluginAnalyzer;

public class PluginAnalyzerPlugin : IUploadPlugin
{
    private readonly ILogger _logger;
    
    public PluginAnalyzerPlugin(ILogger logger)
    {
        _logger = logger;
    }
    
    public bool ValidateAndPopulateKnownMetadata(Mod mod, Stream data, out object? validationFailureInfo)
    {
        string? failureInfo = null;
        
        data.Seek(0, SeekOrigin.Begin);
        using ZipArchive archive = new(data);
        var binaryEntry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".dll", StringComparison.InvariantCultureIgnoreCase));
        var rawManifest = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".manifest", StringComparison.InvariantCultureIgnoreCase));

        byte[]? metadataBytes = null;
        
        // We need to check if this is a Plugin or a Library
        if (rawManifest is not null)
        {
            // This is a library. Read the manifest entry directly.
            using var libraryManifestStream = rawManifest.Open();
            using MemoryStream libraryMemoryStream = new();
            libraryManifestStream.CopyTo(libraryMemoryStream);
            metadataBytes = libraryMemoryStream.ToArray();
        }
        else if (binaryEntry is not null)
        {
            // This is a plugin.
            try
            {
                using var pluginStream = binaryEntry.Open();
                using PEReader reader = new(pluginStream);
                var metadata = reader.GetMetadataReader();

                foreach (var handle in metadata.ManifestResources)
                {
                    var resource = metadata.GetManifestResource(handle);
                    if (!metadata.GetString(resource.Name).EndsWith("manifest.json", StringComparison.InvariantCultureIgnoreCase))
                        continue;

                    var address = reader.PEHeaders.CorHeader!.ResourcesDirectory.RelativeVirtualAddress;
                    var section = reader.GetSectionData(address);
                    var offset = (int)resource.Offset;
                    
                    var resourceReader = section.GetReader(offset, section.Length - offset);
                    metadataBytes = resourceReader.ReadBytes(resourceReader.ReadInt32());
                }
            }
            catch (BadImageFormatException)
            {
                failureInfo = "Could not load plugin: not a managed dynamic linked library.";
            }
            catch (Exception e)
            {
                _logger.Error(e, "Could not load plugin dll {EntryName}", binaryEntry.Name);
                failureInfo = "Could not load plugin: unknown error.";
            }
        }

        if (metadataBytes is null)
        {
            failureInfo ??= "Could not find plugin or library manifest file.";
            validationFailureInfo = failureInfo;
            return false;
        }

        BSIPAManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<BSIPAManifest>(metadataBytes);
        }
        catch
        {
            failureInfo = "Manifest file is not valid JSON";
            validationFailureInfo = failureInfo;
            return false;
        }

        if (manifest is null)
        {
            failureInfo = "Unable to parse manifest.";
            validationFailureInfo = failureInfo;
            return false;
        }

        StringBuilder errors = new();
        if (string.IsNullOrWhiteSpace(manifest.Id))
            errors.AppendLine(@"Manifest is missing an ""id""");
        if (string.IsNullOrWhiteSpace(manifest.Name))
            errors.AppendLine(@"Manifest is missing a ""name""");
        if (manifest.Version == Hive.Versioning.Version.Zero)
            errors.AppendLine(@"Manifest has an invalid ""version"". It must follow SemVer.");

        foreach (var dep in manifest.Dependencies)
        {
            if (!VersionRange.TryParse(dep.Value, out var range))
            {
                errors.AppendLine($@"Dependency ""{dep.Key}"" has an invalid version range.");
                continue;
            }
            mod.Dependencies.Add(new ModReference(dep.Key, range));
        }
        foreach (var conflict in manifest.ConflictsWith)
        {
            if (!VersionRange.TryParse(conflict.Value, out var range))
            {
                errors.AppendLine($@"Confliction ""{conflict.Key}"" has an invalid version range.");
                continue;
            }
            mod.Conflicts.Add(new ModReference(conflict.Key, range));
        }

        var errorText = errors.ToString();
        if (errorText.Length is not 0)
        {
            validationFailureInfo = errorText;
            return false;
        }

        validationFailureInfo = null;
        return true;
    }

    public bool ValidateAndFixUploadedData(Mod mod, ArbitraryAdditionalData originalAdditionalData, out object? validationFailureInfo)
    {
        throw new NotImplementedException();
    }
}