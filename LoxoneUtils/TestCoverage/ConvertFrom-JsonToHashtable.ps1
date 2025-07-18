function ConvertFrom-JsonToHashtable {
    param([string]$Json)
    
    $obj = $Json | ConvertFrom-Json
    $result = @{
        grandfathered = @{}
        permanent = @{}
    }
    
    if ($obj.grandfathered) {
        $obj.grandfathered.PSObject.Properties | ForEach-Object {
            $result.grandfathered[$_.Name] = $_.Value
        }
    }
    
    if ($obj.permanent) {
        $obj.permanent.PSObject.Properties | ForEach-Object {
            $result.permanent[$_.Name] = $_.Value
        }
    }
    
    # Add metadata if present
    if ($obj.metadata) {
        $result.metadata = $obj.metadata
    }
    
    return $result
}
