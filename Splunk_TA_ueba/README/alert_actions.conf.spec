
[send2uba]
param.dataformat = <string>
    * The log type of the UBA alarm.
    * Defaults to "Correlation Search".

param.severity   = <int>
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
     
param.verbose  = [true|false|0|1]
    * Set modular alert action logger to verbose mode.
    * Defaults to "false".