function ResolveVal($val){
   if (-Not $val){
         return  "none"  ;
       }else{
         return $val;
       }
 }

 function ResolveString($val){

     if (-not ([string]::IsNullOrEmpty($val))){
         return $val;
     }else{
          return "none"
      }
 }

 function ResolveBool($val){

     if ($val -eq "true"){
        return $val;
      }else{
          return "false";
      }
 }