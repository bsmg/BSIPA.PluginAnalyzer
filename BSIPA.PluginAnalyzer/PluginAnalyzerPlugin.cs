using System.Collections.Immutable;
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

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.General)
    {
        AllowTrailingCommas = true
    };
    
    public PluginAnalyzerPlugin(ILogger logger)
    {
        _logger = logger;
    }
    
    public bool ValidateAndPopulateKnownMetadata(Mod mod, Stream data, out object? validationFailureInfo)
    {
        string? failureInfo = null;
        
        data.Seek(0, SeekOrigin.Begin);
        using ZipArchive archive = new(data, ZipArchiveMode.Read, true);
        
        // Bypass for BSIPA
        if (archive.Entries.Any(e => e.Name == "IPA.exe"))
        {
            validationFailureInfo = null;
            return true;
        }
        
        var binaryEntry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".dll", StringComparison.InvariantCultureIgnoreCase));
        var rawManifest = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".manifest", StringComparison.InvariantCultureIgnoreCase));
        
        string? assemblyName = null;
        byte[]? metadataBytes = null;
        System.Version? assemblyVersion = null;
        
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
                // Not sure why, but I'm unable to read the plugin data from the zip entry. I need to
                // clone the data and pass in an immutable array. Everything else doesn't work.
                using var pluginStream = binaryEntry.Open();
                using MemoryStream pluginStreamCopy = new();
                pluginStream.CopyTo(pluginStreamCopy);

                var pluginBytes = pluginStreamCopy.ToArray().ToImmutableArray();
                using PEReader reader = new(pluginBytes);
                var metadata = reader.GetMetadataReader();

                var asmdef = metadata.GetAssemblyDefinition();
                assemblyName = asmdef.GetAssemblyName().Name;
                assemblyVersion = asmdef.Version;
                
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
                    break;
                }
            }
            catch (BadImageFormatException e)
            {
                _logger.Error(e, "Could not load plugin dll {EntryName}", binaryEntry.Name);
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

        // Parse the manifest file
        BSIPAManifest? manifest;
        try
        {
            // Trim UTF-8 BOM if it exists
            ReadOnlySpan<byte> manifestData = metadataBytes;
            ReadOnlySpan<byte> utf8Bom = new byte[] { 0xEF, 0xBB, 0xBF };
            if (manifestData.StartsWith(utf8Bom))
                manifestData = manifestData[utf8Bom.Length..];
            
            manifest = JsonSerializer.Deserialize<BSIPAManifest>(manifestData, Options);
        }
        catch (Exception e)
        {
            _logger.Error(e, "Could not parse manifest file from {UploadedMod}", assemblyName);
            validationFailureInfo = "Manifest file is incomplete or invalid JSON.";
            return false;
        }

        if (manifest is null)
        {
            validationFailureInfo = "Unable to parse manifest.";
            return false;
        }

        StringBuilder errors = new();
        if (string.IsNullOrWhiteSpace(manifest.Id))
            errors.AppendLine(@"Manifest is missing an ""id"".");
        if (string.IsNullOrWhiteSpace(manifest.Name))
            errors.AppendLine(@"Manifest is missing a ""name"".");
        if (string.IsNullOrWhiteSpace(manifest.Author))
            errors.AppendLine(@"Manifest is missing an ""author"".");
        if (!manifest.ExtensionData.ContainsKey("description"))
            errors.AppendLine(@"Manifest is missing a ""description"".");
        if (manifest.Version == Hive.Versioning.Version.Zero)
            errors.AppendLine(@"Manifest has an invalid ""version"". It must follow SemVer.");

        if (rawManifest is null) // Not a library
        {
            var assemblyNameMissing = string.IsNullOrWhiteSpace(assemblyName);
            if (assemblyNameMissing)
                errors.AppendLine("Assembly name is missing.");
            
            if (assemblyVersion is null)
            {
                errors.AppendLine("Could not find assembly version.");
            }
            else
            {
                var version = manifest.Version;
                var majorMatches = (ulong)assemblyVersion.Major == version.Major;
                var minorMatches = (ulong)assemblyVersion.Minor == version.Minor;
                var patchMatches = (ulong)assemblyVersion.Build == version.Patch;

                if (!majorMatches || !minorMatches || !patchMatches)
                    errors.AppendLine("Assembly version does not match manifest version.");
            }
        }

        mod.ReadableID = manifest.Id;
        mod.Version = manifest.Version;
        
        // Add dependencies and conflictions
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

        // Setup error text
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
        validationFailureInfo = null;
        return true;
    }
}