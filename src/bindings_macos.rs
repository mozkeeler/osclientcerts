/* automatically generated by rust-bindgen */

pub type SInt32 = ::std::os::raw::c_int;
pub type OSStatus = SInt32;
pub type CFTypeID = ::std::os::raw::c_ulong;
pub type CFTypeRef = *const ::std::os::raw::c_void;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __CFString {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OpaqueSecCertificateRef {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OpaqueSecIdentityRef {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OpaqueSecKeyRef {
    _unused: [u8; 0],
}
pub const errSecSuccess: _bindgen_ty_8 = 0;
pub const errSecUnimplemented: _bindgen_ty_8 = -4;
pub const errSecDiskFull: _bindgen_ty_8 = -34;
pub const errSecDskFull: _bindgen_ty_8 = -34;
pub const errSecIO: _bindgen_ty_8 = -36;
pub const errSecOpWr: _bindgen_ty_8 = -49;
pub const errSecParam: _bindgen_ty_8 = -50;
pub const errSecWrPerm: _bindgen_ty_8 = -61;
pub const errSecAllocate: _bindgen_ty_8 = -108;
pub const errSecUserCanceled: _bindgen_ty_8 = -128;
pub const errSecBadReq: _bindgen_ty_8 = -909;
pub const errSecInternalComponent: _bindgen_ty_8 = -2070;
pub const errSecCoreFoundationUnknown: _bindgen_ty_8 = -4960;
pub const errSecMissingEntitlement: _bindgen_ty_8 = -34018;
pub const errSecNotAvailable: _bindgen_ty_8 = -25291;
pub const errSecReadOnly: _bindgen_ty_8 = -25292;
pub const errSecAuthFailed: _bindgen_ty_8 = -25293;
pub const errSecNoSuchKeychain: _bindgen_ty_8 = -25294;
pub const errSecInvalidKeychain: _bindgen_ty_8 = -25295;
pub const errSecDuplicateKeychain: _bindgen_ty_8 = -25296;
pub const errSecDuplicateCallback: _bindgen_ty_8 = -25297;
pub const errSecInvalidCallback: _bindgen_ty_8 = -25298;
pub const errSecDuplicateItem: _bindgen_ty_8 = -25299;
pub const errSecItemNotFound: _bindgen_ty_8 = -25300;
pub const errSecBufferTooSmall: _bindgen_ty_8 = -25301;
pub const errSecDataTooLarge: _bindgen_ty_8 = -25302;
pub const errSecNoSuchAttr: _bindgen_ty_8 = -25303;
pub const errSecInvalidItemRef: _bindgen_ty_8 = -25304;
pub const errSecInvalidSearchRef: _bindgen_ty_8 = -25305;
pub const errSecNoSuchClass: _bindgen_ty_8 = -25306;
pub const errSecNoDefaultKeychain: _bindgen_ty_8 = -25307;
pub const errSecInteractionNotAllowed: _bindgen_ty_8 = -25308;
pub const errSecReadOnlyAttr: _bindgen_ty_8 = -25309;
pub const errSecWrongSecVersion: _bindgen_ty_8 = -25310;
pub const errSecKeySizeNotAllowed: _bindgen_ty_8 = -25311;
pub const errSecNoStorageModule: _bindgen_ty_8 = -25312;
pub const errSecNoCertificateModule: _bindgen_ty_8 = -25313;
pub const errSecNoPolicyModule: _bindgen_ty_8 = -25314;
pub const errSecInteractionRequired: _bindgen_ty_8 = -25315;
pub const errSecDataNotAvailable: _bindgen_ty_8 = -25316;
pub const errSecDataNotModifiable: _bindgen_ty_8 = -25317;
pub const errSecCreateChainFailed: _bindgen_ty_8 = -25318;
pub const errSecInvalidPrefsDomain: _bindgen_ty_8 = -25319;
pub const errSecInDarkWake: _bindgen_ty_8 = -25320;
pub const errSecACLNotSimple: _bindgen_ty_8 = -25240;
pub const errSecPolicyNotFound: _bindgen_ty_8 = -25241;
pub const errSecInvalidTrustSetting: _bindgen_ty_8 = -25242;
pub const errSecNoAccessForItem: _bindgen_ty_8 = -25243;
pub const errSecInvalidOwnerEdit: _bindgen_ty_8 = -25244;
pub const errSecTrustNotAvailable: _bindgen_ty_8 = -25245;
pub const errSecUnsupportedFormat: _bindgen_ty_8 = -25256;
pub const errSecUnknownFormat: _bindgen_ty_8 = -25257;
pub const errSecKeyIsSensitive: _bindgen_ty_8 = -25258;
pub const errSecMultiplePrivKeys: _bindgen_ty_8 = -25259;
pub const errSecPassphraseRequired: _bindgen_ty_8 = -25260;
pub const errSecInvalidPasswordRef: _bindgen_ty_8 = -25261;
pub const errSecInvalidTrustSettings: _bindgen_ty_8 = -25262;
pub const errSecNoTrustSettings: _bindgen_ty_8 = -25263;
pub const errSecPkcs12VerifyFailure: _bindgen_ty_8 = -25264;
pub const errSecNotSigner: _bindgen_ty_8 = -26267;
pub const errSecDecode: _bindgen_ty_8 = -26275;
pub const errSecServiceNotAvailable: _bindgen_ty_8 = -67585;
pub const errSecInsufficientClientID: _bindgen_ty_8 = -67586;
pub const errSecDeviceReset: _bindgen_ty_8 = -67587;
pub const errSecDeviceFailed: _bindgen_ty_8 = -67588;
pub const errSecAppleAddAppACLSubject: _bindgen_ty_8 = -67589;
pub const errSecApplePublicKeyIncomplete: _bindgen_ty_8 = -67590;
pub const errSecAppleSignatureMismatch: _bindgen_ty_8 = -67591;
pub const errSecAppleInvalidKeyStartDate: _bindgen_ty_8 = -67592;
pub const errSecAppleInvalidKeyEndDate: _bindgen_ty_8 = -67593;
pub const errSecConversionError: _bindgen_ty_8 = -67594;
pub const errSecAppleSSLv2Rollback: _bindgen_ty_8 = -67595;
pub const errSecQuotaExceeded: _bindgen_ty_8 = -67596;
pub const errSecFileTooBig: _bindgen_ty_8 = -67597;
pub const errSecInvalidDatabaseBlob: _bindgen_ty_8 = -67598;
pub const errSecInvalidKeyBlob: _bindgen_ty_8 = -67599;
pub const errSecIncompatibleDatabaseBlob: _bindgen_ty_8 = -67600;
pub const errSecIncompatibleKeyBlob: _bindgen_ty_8 = -67601;
pub const errSecHostNameMismatch: _bindgen_ty_8 = -67602;
pub const errSecUnknownCriticalExtensionFlag: _bindgen_ty_8 = -67603;
pub const errSecNoBasicConstraints: _bindgen_ty_8 = -67604;
pub const errSecNoBasicConstraintsCA: _bindgen_ty_8 = -67605;
pub const errSecInvalidAuthorityKeyID: _bindgen_ty_8 = -67606;
pub const errSecInvalidSubjectKeyID: _bindgen_ty_8 = -67607;
pub const errSecInvalidKeyUsageForPolicy: _bindgen_ty_8 = -67608;
pub const errSecInvalidExtendedKeyUsage: _bindgen_ty_8 = -67609;
pub const errSecInvalidIDLinkage: _bindgen_ty_8 = -67610;
pub const errSecPathLengthConstraintExceeded: _bindgen_ty_8 = -67611;
pub const errSecInvalidRoot: _bindgen_ty_8 = -67612;
pub const errSecCRLExpired: _bindgen_ty_8 = -67613;
pub const errSecCRLNotValidYet: _bindgen_ty_8 = -67614;
pub const errSecCRLNotFound: _bindgen_ty_8 = -67615;
pub const errSecCRLServerDown: _bindgen_ty_8 = -67616;
pub const errSecCRLBadURI: _bindgen_ty_8 = -67617;
pub const errSecUnknownCertExtension: _bindgen_ty_8 = -67618;
pub const errSecUnknownCRLExtension: _bindgen_ty_8 = -67619;
pub const errSecCRLNotTrusted: _bindgen_ty_8 = -67620;
pub const errSecCRLPolicyFailed: _bindgen_ty_8 = -67621;
pub const errSecIDPFailure: _bindgen_ty_8 = -67622;
pub const errSecSMIMEEmailAddressesNotFound: _bindgen_ty_8 = -67623;
pub const errSecSMIMEBadExtendedKeyUsage: _bindgen_ty_8 = -67624;
pub const errSecSMIMEBadKeyUsage: _bindgen_ty_8 = -67625;
pub const errSecSMIMEKeyUsageNotCritical: _bindgen_ty_8 = -67626;
pub const errSecSMIMENoEmailAddress: _bindgen_ty_8 = -67627;
pub const errSecSMIMESubjAltNameNotCritical: _bindgen_ty_8 = -67628;
pub const errSecSSLBadExtendedKeyUsage: _bindgen_ty_8 = -67629;
pub const errSecOCSPBadResponse: _bindgen_ty_8 = -67630;
pub const errSecOCSPBadRequest: _bindgen_ty_8 = -67631;
pub const errSecOCSPUnavailable: _bindgen_ty_8 = -67632;
pub const errSecOCSPStatusUnrecognized: _bindgen_ty_8 = -67633;
pub const errSecEndOfData: _bindgen_ty_8 = -67634;
pub const errSecIncompleteCertRevocationCheck: _bindgen_ty_8 = -67635;
pub const errSecNetworkFailure: _bindgen_ty_8 = -67636;
pub const errSecOCSPNotTrustedToAnchor: _bindgen_ty_8 = -67637;
pub const errSecRecordModified: _bindgen_ty_8 = -67638;
pub const errSecOCSPSignatureError: _bindgen_ty_8 = -67639;
pub const errSecOCSPNoSigner: _bindgen_ty_8 = -67640;
pub const errSecOCSPResponderMalformedReq: _bindgen_ty_8 = -67641;
pub const errSecOCSPResponderInternalError: _bindgen_ty_8 = -67642;
pub const errSecOCSPResponderTryLater: _bindgen_ty_8 = -67643;
pub const errSecOCSPResponderSignatureRequired: _bindgen_ty_8 = -67644;
pub const errSecOCSPResponderUnauthorized: _bindgen_ty_8 = -67645;
pub const errSecOCSPResponseNonceMismatch: _bindgen_ty_8 = -67646;
pub const errSecCodeSigningBadCertChainLength: _bindgen_ty_8 = -67647;
pub const errSecCodeSigningNoBasicConstraints: _bindgen_ty_8 = -67648;
pub const errSecCodeSigningBadPathLengthConstraint: _bindgen_ty_8 = -67649;
pub const errSecCodeSigningNoExtendedKeyUsage: _bindgen_ty_8 = -67650;
pub const errSecCodeSigningDevelopment: _bindgen_ty_8 = -67651;
pub const errSecResourceSignBadCertChainLength: _bindgen_ty_8 = -67652;
pub const errSecResourceSignBadExtKeyUsage: _bindgen_ty_8 = -67653;
pub const errSecTrustSettingDeny: _bindgen_ty_8 = -67654;
pub const errSecInvalidSubjectName: _bindgen_ty_8 = -67655;
pub const errSecUnknownQualifiedCertStatement: _bindgen_ty_8 = -67656;
pub const errSecMobileMeRequestQueued: _bindgen_ty_8 = -67657;
pub const errSecMobileMeRequestRedirected: _bindgen_ty_8 = -67658;
pub const errSecMobileMeServerError: _bindgen_ty_8 = -67659;
pub const errSecMobileMeServerNotAvailable: _bindgen_ty_8 = -67660;
pub const errSecMobileMeServerAlreadyExists: _bindgen_ty_8 = -67661;
pub const errSecMobileMeServerServiceErr: _bindgen_ty_8 = -67662;
pub const errSecMobileMeRequestAlreadyPending: _bindgen_ty_8 = -67663;
pub const errSecMobileMeNoRequestPending: _bindgen_ty_8 = -67664;
pub const errSecMobileMeCSRVerifyFailure: _bindgen_ty_8 = -67665;
pub const errSecMobileMeFailedConsistencyCheck: _bindgen_ty_8 = -67666;
pub const errSecNotInitialized: _bindgen_ty_8 = -67667;
pub const errSecInvalidHandleUsage: _bindgen_ty_8 = -67668;
pub const errSecPVCReferentNotFound: _bindgen_ty_8 = -67669;
pub const errSecFunctionIntegrityFail: _bindgen_ty_8 = -67670;
pub const errSecInternalError: _bindgen_ty_8 = -67671;
pub const errSecMemoryError: _bindgen_ty_8 = -67672;
pub const errSecInvalidData: _bindgen_ty_8 = -67673;
pub const errSecMDSError: _bindgen_ty_8 = -67674;
pub const errSecInvalidPointer: _bindgen_ty_8 = -67675;
pub const errSecSelfCheckFailed: _bindgen_ty_8 = -67676;
pub const errSecFunctionFailed: _bindgen_ty_8 = -67677;
pub const errSecModuleManifestVerifyFailed: _bindgen_ty_8 = -67678;
pub const errSecInvalidGUID: _bindgen_ty_8 = -67679;
pub const errSecInvalidHandle: _bindgen_ty_8 = -67680;
pub const errSecInvalidDBList: _bindgen_ty_8 = -67681;
pub const errSecInvalidPassthroughID: _bindgen_ty_8 = -67682;
pub const errSecInvalidNetworkAddress: _bindgen_ty_8 = -67683;
pub const errSecCRLAlreadySigned: _bindgen_ty_8 = -67684;
pub const errSecInvalidNumberOfFields: _bindgen_ty_8 = -67685;
pub const errSecVerificationFailure: _bindgen_ty_8 = -67686;
pub const errSecUnknownTag: _bindgen_ty_8 = -67687;
pub const errSecInvalidSignature: _bindgen_ty_8 = -67688;
pub const errSecInvalidName: _bindgen_ty_8 = -67689;
pub const errSecInvalidCertificateRef: _bindgen_ty_8 = -67690;
pub const errSecInvalidCertificateGroup: _bindgen_ty_8 = -67691;
pub const errSecTagNotFound: _bindgen_ty_8 = -67692;
pub const errSecInvalidQuery: _bindgen_ty_8 = -67693;
pub const errSecInvalidValue: _bindgen_ty_8 = -67694;
pub const errSecCallbackFailed: _bindgen_ty_8 = -67695;
pub const errSecACLDeleteFailed: _bindgen_ty_8 = -67696;
pub const errSecACLReplaceFailed: _bindgen_ty_8 = -67697;
pub const errSecACLAddFailed: _bindgen_ty_8 = -67698;
pub const errSecACLChangeFailed: _bindgen_ty_8 = -67699;
pub const errSecInvalidAccessCredentials: _bindgen_ty_8 = -67700;
pub const errSecInvalidRecord: _bindgen_ty_8 = -67701;
pub const errSecInvalidACL: _bindgen_ty_8 = -67702;
pub const errSecInvalidSampleValue: _bindgen_ty_8 = -67703;
pub const errSecIncompatibleVersion: _bindgen_ty_8 = -67704;
pub const errSecPrivilegeNotGranted: _bindgen_ty_8 = -67705;
pub const errSecInvalidScope: _bindgen_ty_8 = -67706;
pub const errSecPVCAlreadyConfigured: _bindgen_ty_8 = -67707;
pub const errSecInvalidPVC: _bindgen_ty_8 = -67708;
pub const errSecEMMLoadFailed: _bindgen_ty_8 = -67709;
pub const errSecEMMUnloadFailed: _bindgen_ty_8 = -67710;
pub const errSecAddinLoadFailed: _bindgen_ty_8 = -67711;
pub const errSecInvalidKeyRef: _bindgen_ty_8 = -67712;
pub const errSecInvalidKeyHierarchy: _bindgen_ty_8 = -67713;
pub const errSecAddinUnloadFailed: _bindgen_ty_8 = -67714;
pub const errSecLibraryReferenceNotFound: _bindgen_ty_8 = -67715;
pub const errSecInvalidAddinFunctionTable: _bindgen_ty_8 = -67716;
pub const errSecInvalidServiceMask: _bindgen_ty_8 = -67717;
pub const errSecModuleNotLoaded: _bindgen_ty_8 = -67718;
pub const errSecInvalidSubServiceID: _bindgen_ty_8 = -67719;
pub const errSecAttributeNotInContext: _bindgen_ty_8 = -67720;
pub const errSecModuleManagerInitializeFailed: _bindgen_ty_8 = -67721;
pub const errSecModuleManagerNotFound: _bindgen_ty_8 = -67722;
pub const errSecEventNotificationCallbackNotFound: _bindgen_ty_8 = -67723;
pub const errSecInputLengthError: _bindgen_ty_8 = -67724;
pub const errSecOutputLengthError: _bindgen_ty_8 = -67725;
pub const errSecPrivilegeNotSupported: _bindgen_ty_8 = -67726;
pub const errSecDeviceError: _bindgen_ty_8 = -67727;
pub const errSecAttachHandleBusy: _bindgen_ty_8 = -67728;
pub const errSecNotLoggedIn: _bindgen_ty_8 = -67729;
pub const errSecAlgorithmMismatch: _bindgen_ty_8 = -67730;
pub const errSecKeyUsageIncorrect: _bindgen_ty_8 = -67731;
pub const errSecKeyBlobTypeIncorrect: _bindgen_ty_8 = -67732;
pub const errSecKeyHeaderInconsistent: _bindgen_ty_8 = -67733;
pub const errSecUnsupportedKeyFormat: _bindgen_ty_8 = -67734;
pub const errSecUnsupportedKeySize: _bindgen_ty_8 = -67735;
pub const errSecInvalidKeyUsageMask: _bindgen_ty_8 = -67736;
pub const errSecUnsupportedKeyUsageMask: _bindgen_ty_8 = -67737;
pub const errSecInvalidKeyAttributeMask: _bindgen_ty_8 = -67738;
pub const errSecUnsupportedKeyAttributeMask: _bindgen_ty_8 = -67739;
pub const errSecInvalidKeyLabel: _bindgen_ty_8 = -67740;
pub const errSecUnsupportedKeyLabel: _bindgen_ty_8 = -67741;
pub const errSecInvalidKeyFormat: _bindgen_ty_8 = -67742;
pub const errSecUnsupportedVectorOfBuffers: _bindgen_ty_8 = -67743;
pub const errSecInvalidInputVector: _bindgen_ty_8 = -67744;
pub const errSecInvalidOutputVector: _bindgen_ty_8 = -67745;
pub const errSecInvalidContext: _bindgen_ty_8 = -67746;
pub const errSecInvalidAlgorithm: _bindgen_ty_8 = -67747;
pub const errSecInvalidAttributeKey: _bindgen_ty_8 = -67748;
pub const errSecMissingAttributeKey: _bindgen_ty_8 = -67749;
pub const errSecInvalidAttributeInitVector: _bindgen_ty_8 = -67750;
pub const errSecMissingAttributeInitVector: _bindgen_ty_8 = -67751;
pub const errSecInvalidAttributeSalt: _bindgen_ty_8 = -67752;
pub const errSecMissingAttributeSalt: _bindgen_ty_8 = -67753;
pub const errSecInvalidAttributePadding: _bindgen_ty_8 = -67754;
pub const errSecMissingAttributePadding: _bindgen_ty_8 = -67755;
pub const errSecInvalidAttributeRandom: _bindgen_ty_8 = -67756;
pub const errSecMissingAttributeRandom: _bindgen_ty_8 = -67757;
pub const errSecInvalidAttributeSeed: _bindgen_ty_8 = -67758;
pub const errSecMissingAttributeSeed: _bindgen_ty_8 = -67759;
pub const errSecInvalidAttributePassphrase: _bindgen_ty_8 = -67760;
pub const errSecMissingAttributePassphrase: _bindgen_ty_8 = -67761;
pub const errSecInvalidAttributeKeyLength: _bindgen_ty_8 = -67762;
pub const errSecMissingAttributeKeyLength: _bindgen_ty_8 = -67763;
pub const errSecInvalidAttributeBlockSize: _bindgen_ty_8 = -67764;
pub const errSecMissingAttributeBlockSize: _bindgen_ty_8 = -67765;
pub const errSecInvalidAttributeOutputSize: _bindgen_ty_8 = -67766;
pub const errSecMissingAttributeOutputSize: _bindgen_ty_8 = -67767;
pub const errSecInvalidAttributeRounds: _bindgen_ty_8 = -67768;
pub const errSecMissingAttributeRounds: _bindgen_ty_8 = -67769;
pub const errSecInvalidAlgorithmParms: _bindgen_ty_8 = -67770;
pub const errSecMissingAlgorithmParms: _bindgen_ty_8 = -67771;
pub const errSecInvalidAttributeLabel: _bindgen_ty_8 = -67772;
pub const errSecMissingAttributeLabel: _bindgen_ty_8 = -67773;
pub const errSecInvalidAttributeKeyType: _bindgen_ty_8 = -67774;
pub const errSecMissingAttributeKeyType: _bindgen_ty_8 = -67775;
pub const errSecInvalidAttributeMode: _bindgen_ty_8 = -67776;
pub const errSecMissingAttributeMode: _bindgen_ty_8 = -67777;
pub const errSecInvalidAttributeEffectiveBits: _bindgen_ty_8 = -67778;
pub const errSecMissingAttributeEffectiveBits: _bindgen_ty_8 = -67779;
pub const errSecInvalidAttributeStartDate: _bindgen_ty_8 = -67780;
pub const errSecMissingAttributeStartDate: _bindgen_ty_8 = -67781;
pub const errSecInvalidAttributeEndDate: _bindgen_ty_8 = -67782;
pub const errSecMissingAttributeEndDate: _bindgen_ty_8 = -67783;
pub const errSecInvalidAttributeVersion: _bindgen_ty_8 = -67784;
pub const errSecMissingAttributeVersion: _bindgen_ty_8 = -67785;
pub const errSecInvalidAttributePrime: _bindgen_ty_8 = -67786;
pub const errSecMissingAttributePrime: _bindgen_ty_8 = -67787;
pub const errSecInvalidAttributeBase: _bindgen_ty_8 = -67788;
pub const errSecMissingAttributeBase: _bindgen_ty_8 = -67789;
pub const errSecInvalidAttributeSubprime: _bindgen_ty_8 = -67790;
pub const errSecMissingAttributeSubprime: _bindgen_ty_8 = -67791;
pub const errSecInvalidAttributeIterationCount: _bindgen_ty_8 = -67792;
pub const errSecMissingAttributeIterationCount: _bindgen_ty_8 = -67793;
pub const errSecInvalidAttributeDLDBHandle: _bindgen_ty_8 = -67794;
pub const errSecMissingAttributeDLDBHandle: _bindgen_ty_8 = -67795;
pub const errSecInvalidAttributeAccessCredentials: _bindgen_ty_8 = -67796;
pub const errSecMissingAttributeAccessCredentials: _bindgen_ty_8 = -67797;
pub const errSecInvalidAttributePublicKeyFormat: _bindgen_ty_8 = -67798;
pub const errSecMissingAttributePublicKeyFormat: _bindgen_ty_8 = -67799;
pub const errSecInvalidAttributePrivateKeyFormat: _bindgen_ty_8 = -67800;
pub const errSecMissingAttributePrivateKeyFormat: _bindgen_ty_8 = -67801;
pub const errSecInvalidAttributeSymmetricKeyFormat: _bindgen_ty_8 = -67802;
pub const errSecMissingAttributeSymmetricKeyFormat: _bindgen_ty_8 = -67803;
pub const errSecInvalidAttributeWrappedKeyFormat: _bindgen_ty_8 = -67804;
pub const errSecMissingAttributeWrappedKeyFormat: _bindgen_ty_8 = -67805;
pub const errSecStagedOperationInProgress: _bindgen_ty_8 = -67806;
pub const errSecStagedOperationNotStarted: _bindgen_ty_8 = -67807;
pub const errSecVerifyFailed: _bindgen_ty_8 = -67808;
pub const errSecQuerySizeUnknown: _bindgen_ty_8 = -67809;
pub const errSecBlockSizeMismatch: _bindgen_ty_8 = -67810;
pub const errSecPublicKeyInconsistent: _bindgen_ty_8 = -67811;
pub const errSecDeviceVerifyFailed: _bindgen_ty_8 = -67812;
pub const errSecInvalidLoginName: _bindgen_ty_8 = -67813;
pub const errSecAlreadyLoggedIn: _bindgen_ty_8 = -67814;
pub const errSecInvalidDigestAlgorithm: _bindgen_ty_8 = -67815;
pub const errSecInvalidCRLGroup: _bindgen_ty_8 = -67816;
pub const errSecCertificateCannotOperate: _bindgen_ty_8 = -67817;
pub const errSecCertificateExpired: _bindgen_ty_8 = -67818;
pub const errSecCertificateNotValidYet: _bindgen_ty_8 = -67819;
pub const errSecCertificateRevoked: _bindgen_ty_8 = -67820;
pub const errSecCertificateSuspended: _bindgen_ty_8 = -67821;
pub const errSecInsufficientCredentials: _bindgen_ty_8 = -67822;
pub const errSecInvalidAction: _bindgen_ty_8 = -67823;
pub const errSecInvalidAuthority: _bindgen_ty_8 = -67824;
pub const errSecVerifyActionFailed: _bindgen_ty_8 = -67825;
pub const errSecInvalidCertAuthority: _bindgen_ty_8 = -67826;
pub const errSecInvaldCRLAuthority: _bindgen_ty_8 = -67827;
pub const errSecInvalidCRLEncoding: _bindgen_ty_8 = -67828;
pub const errSecInvalidCRLType: _bindgen_ty_8 = -67829;
pub const errSecInvalidCRL: _bindgen_ty_8 = -67830;
pub const errSecInvalidFormType: _bindgen_ty_8 = -67831;
pub const errSecInvalidID: _bindgen_ty_8 = -67832;
pub const errSecInvalidIdentifier: _bindgen_ty_8 = -67833;
pub const errSecInvalidIndex: _bindgen_ty_8 = -67834;
pub const errSecInvalidPolicyIdentifiers: _bindgen_ty_8 = -67835;
pub const errSecInvalidTimeString: _bindgen_ty_8 = -67836;
pub const errSecInvalidReason: _bindgen_ty_8 = -67837;
pub const errSecInvalidRequestInputs: _bindgen_ty_8 = -67838;
pub const errSecInvalidResponseVector: _bindgen_ty_8 = -67839;
pub const errSecInvalidStopOnPolicy: _bindgen_ty_8 = -67840;
pub const errSecInvalidTuple: _bindgen_ty_8 = -67841;
pub const errSecMultipleValuesUnsupported: _bindgen_ty_8 = -67842;
pub const errSecNotTrusted: _bindgen_ty_8 = -67843;
pub const errSecNoDefaultAuthority: _bindgen_ty_8 = -67844;
pub const errSecRejectedForm: _bindgen_ty_8 = -67845;
pub const errSecRequestLost: _bindgen_ty_8 = -67846;
pub const errSecRequestRejected: _bindgen_ty_8 = -67847;
pub const errSecUnsupportedAddressType: _bindgen_ty_8 = -67848;
pub const errSecUnsupportedService: _bindgen_ty_8 = -67849;
pub const errSecInvalidTupleGroup: _bindgen_ty_8 = -67850;
pub const errSecInvalidBaseACLs: _bindgen_ty_8 = -67851;
pub const errSecInvalidTupleCredendtials: _bindgen_ty_8 = -67852;
pub const errSecInvalidEncoding: _bindgen_ty_8 = -67853;
pub const errSecInvalidValidityPeriod: _bindgen_ty_8 = -67854;
pub const errSecInvalidRequestor: _bindgen_ty_8 = -67855;
pub const errSecRequestDescriptor: _bindgen_ty_8 = -67856;
pub const errSecInvalidBundleInfo: _bindgen_ty_8 = -67857;
pub const errSecInvalidCRLIndex: _bindgen_ty_8 = -67858;
pub const errSecNoFieldValues: _bindgen_ty_8 = -67859;
pub const errSecUnsupportedFieldFormat: _bindgen_ty_8 = -67860;
pub const errSecUnsupportedIndexInfo: _bindgen_ty_8 = -67861;
pub const errSecUnsupportedLocality: _bindgen_ty_8 = -67862;
pub const errSecUnsupportedNumAttributes: _bindgen_ty_8 = -67863;
pub const errSecUnsupportedNumIndexes: _bindgen_ty_8 = -67864;
pub const errSecUnsupportedNumRecordTypes: _bindgen_ty_8 = -67865;
pub const errSecFieldSpecifiedMultiple: _bindgen_ty_8 = -67866;
pub const errSecIncompatibleFieldFormat: _bindgen_ty_8 = -67867;
pub const errSecInvalidParsingModule: _bindgen_ty_8 = -67868;
pub const errSecDatabaseLocked: _bindgen_ty_8 = -67869;
pub const errSecDatastoreIsOpen: _bindgen_ty_8 = -67870;
pub const errSecMissingValue: _bindgen_ty_8 = -67871;
pub const errSecUnsupportedQueryLimits: _bindgen_ty_8 = -67872;
pub const errSecUnsupportedNumSelectionPreds: _bindgen_ty_8 = -67873;
pub const errSecUnsupportedOperator: _bindgen_ty_8 = -67874;
pub const errSecInvalidDBLocation: _bindgen_ty_8 = -67875;
pub const errSecInvalidAccessRequest: _bindgen_ty_8 = -67876;
pub const errSecInvalidIndexInfo: _bindgen_ty_8 = -67877;
pub const errSecInvalidNewOwner: _bindgen_ty_8 = -67878;
pub const errSecInvalidModifyMode: _bindgen_ty_8 = -67879;
pub const errSecMissingRequiredExtension: _bindgen_ty_8 = -67880;
pub const errSecExtendedKeyUsageNotCritical: _bindgen_ty_8 = -67881;
pub const errSecTimestampMissing: _bindgen_ty_8 = -67882;
pub const errSecTimestampInvalid: _bindgen_ty_8 = -67883;
pub const errSecTimestampNotTrusted: _bindgen_ty_8 = -67884;
pub const errSecTimestampServiceNotAvailable: _bindgen_ty_8 = -67885;
pub const errSecTimestampBadAlg: _bindgen_ty_8 = -67886;
pub const errSecTimestampBadRequest: _bindgen_ty_8 = -67887;
pub const errSecTimestampBadDataFormat: _bindgen_ty_8 = -67888;
pub const errSecTimestampTimeNotAvailable: _bindgen_ty_8 = -67889;
pub const errSecTimestampUnacceptedPolicy: _bindgen_ty_8 = -67890;
pub const errSecTimestampUnacceptedExtension: _bindgen_ty_8 = -67891;
pub const errSecTimestampAddInfoNotAvailable: _bindgen_ty_8 = -67892;
pub const errSecTimestampSystemFailure: _bindgen_ty_8 = -67893;
pub const errSecSigningTimeMissing: _bindgen_ty_8 = -67894;
pub const errSecTimestampRejection: _bindgen_ty_8 = -67895;
pub const errSecTimestampWaiting: _bindgen_ty_8 = -67896;
pub const errSecTimestampRevocationWarning: _bindgen_ty_8 = -67897;
pub const errSecTimestampRevocationNotification: _bindgen_ty_8 = -67898;
pub type _bindgen_ty_8 = i32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __CFData {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __CFDictionary {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __CFError {
    _unused: [u8; 0],
}
extern "C" {
    pub fn SecCertificateGetTypeID() -> CFTypeID;
}
extern "C" {
    pub fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;
}
extern "C" {
    pub fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) -> CFStringRef;
}
extern "C" {
    pub fn SecCertificateCopyNormalizedIssuerSequence(certificate: SecCertificateRef) -> CFDataRef;
}
extern "C" {
    pub fn SecCertificateCopyNormalizedSubjectSequence(certificate: SecCertificateRef)
        -> CFDataRef;
}
extern "C" {
    pub fn SecCertificateCopyKey(certificate: SecCertificateRef) -> SecKeyRef;
}
extern "C" {
    pub fn SecCertificateCopySerialNumberData(
        certificate: SecCertificateRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
}
extern "C" {
    pub fn SecIdentityGetTypeID() -> CFTypeID;
}
extern "C" {
    pub fn SecIdentityCopyCertificate(
        identityRef: SecIdentityRef,
        certificateRef: *mut SecCertificateRef,
    ) -> OSStatus;
}
extern "C" {
    pub fn SecIdentityCopyPrivateKey(
        identityRef: SecIdentityRef,
        privateKeyRef: *mut SecKeyRef,
    ) -> OSStatus;
}
extern "C" {
    pub static kSecClass: CFStringRef;
}
extern "C" {
    pub static kSecClassIdentity: CFStringRef;
}
extern "C" {
    pub static kSecAttrKeyType: CFStringRef;
}
extern "C" {
    pub static kSecAttrKeySizeInBits: CFStringRef;
}
extern "C" {
    pub static kSecAttrKeyTypeRSA: CFStringRef;
}
extern "C" {
    pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
}
extern "C" {
    pub static kSecMatchLimit: CFStringRef;
}
extern "C" {
    pub static kSecMatchLimitAll: CFStringRef;
}
extern "C" {
    pub static kSecReturnRef: CFStringRef;
}
extern "C" {
    pub fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
}
extern "C" {
    pub fn SecKeyGetTypeID() -> CFTypeID;
}
extern "C" {
    pub fn SecKeyCopyExternalRepresentation(key: SecKeyRef, error: *mut CFErrorRef) -> CFDataRef;
}
extern "C" {
    pub fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
}
pub type SecKeyAlgorithm = CFStringRef;
extern "C" {
    pub static kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw: SecKeyAlgorithm;
}
extern "C" {
    pub static kSecKeyAlgorithmECDSASignatureDigestX962: SecKeyAlgorithm;
}
extern "C" {
    pub fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        dataToSign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
}
