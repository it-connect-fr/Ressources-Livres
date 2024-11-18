function Analyze-NmapXml {
    <#
    .SYNOPSIS
    Analyse un fichier XML de sortie Nmap et retourne les informations sur les hôtes et les ports.

    .DESCRIPTION
    Cette fonction charge un fichier XML généré par Nmap, extrait les adresses IP des hôtes,
    ainsi que les informations sur les ports ouverts, les services, les versions et les CPE.

    .PARAMETER FilePath
    Chemin d'accès au fichier XML Nmap à analyser.

    .OUTPUTS
    Retourne une liste d'objets PowerShell personnalisés contenant les informations sur les hôtes et les ports.

    .EXAMPLE
    $results = Analyze-NmapXml -FilePath ".\nmap.xml"

    .AUTHOR
    Mickael Dorigny - IT-Connect.fr
    #>

    param (
        [string]$FilePath
    )

    # Chargement et parsing du fichier XML
    $xml = [xml](Get-Content -Path $FilePath)

    # Création d'une liste pour stocker les objets
    $results = @()

    # Parcours de chaque hôte dans le fichier XML
    foreach ($scannedHost in $xml.nmaprun.host) {
        $ip = $scannedHost.address.addr

        foreach ($port in $scannedHost.ports.port) {
            $protocol = $port.protocol
            $portid = $port.portid
            $state = $port.state.state
            $service = $port.service
            $service_product = $service.product
            $service_version = $service.version
            $service_extrainfo = $service.extrainfo
            $cpe = if ($service.cpe) { $service.cpe } else { "" }

            $entry = [PSCustomObject]@{
                ip = $ip
                port = $portid
                state = $state
                product = $service_product
                version = $service_version
                extrainfo = $service_extrainfo
                cpe = $cpe
            }

            $results += $entry
        }
    }

    return $results
}
