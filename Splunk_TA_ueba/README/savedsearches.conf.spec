
action.send2uba = [0|1]
    * Enable send2uba action
    
action.send2uba.param.severity = <int>
    * The severity of the UBA alarm.
    * If "severity" exists as field in the result
      it will be taken in favor of this setting.
    * Valid values are 1-10.
    * Mappings from human readable strings are as follows:
      informational -> 1
      low           -> 3
      medium        -> 5
      high          -> 7
      critical      -> 9
    * Defaults to 5.