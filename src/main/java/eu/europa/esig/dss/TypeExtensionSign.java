package eu.europa.esig.dss;

public enum TypeExtensionSign {


	IS_PARALLEL("isParallel"),
	IS_AUTOMATIC("isAutomatic"),
	IS_COUNTERSIGNATURE("isCounterSign"),
	IS_DETACHED("isDetached"),
	IS_NESTED("isNested"),
	IS_EXTENDED("isExtended"),
	IS_ONLY_MARK("isOnlyMark"),
	IS_ONLY_HASH("isOnlyHash");
	
   private String nomeFirma;

   TypeExtensionSign(String nomeFirma) {
       this.nomeFirma = nomeFirma;
   }

   public String nomeFirma() {
       return nomeFirma;
   }
}
