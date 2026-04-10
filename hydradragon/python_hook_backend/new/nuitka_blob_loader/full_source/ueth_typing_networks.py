# Reconstructed from integrated Nuitka blob
# Module: ueth_typing.networks


IntEnum class defining EVM-compatible network name enums as their respective
``ChainID`` int values.
To learn more about chain ids, see `CAIP-2 <https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md>`_ for details.
The list of chain ids is available from the `ethereum-lists/chains <https://github.com/ethereum-lists/chains>`_ repository.
For a complete list of supported enums, see `eth_typing/networks.py <https://github.com/ethereum/eth-typing/blob/f9cfaa35e2c1ac868ffe9256174aaac3b882c8d1/eth_typing/networks.py>`_.
.. doctest::
>>> from eth_typing import ChainId
>>> ChainId(1)
<ChainId.ETH: 1>
>>> ChainId(10)
<ChainId.OETH: 10>
a__qualname__
aETH
l aEXP
l aROP
l aRIN
l aGOR
l aKOT
l aTCH
l aUBQ
l	aTUBQ
l
aOETH
l aMETA
l aKAL
laDSTG
l aFLR
l aDIODE
l aCFLR
l aTFI
l aTST
l aSGB
l aESC
l aESCT
l aELADID
l aELADIDT
l aKARDIACHAIN
l aCRO
l aL1TEST
l aSHIB
l aBOBARINKEBY
l aL1
l aRSK
l aTRSK
l aGOODT
l!aGOOD
l"aSCAI
l#aTBWG
l$aDX
l%aXPLA
l&aVAL
l'aU2U
l(aTELOSEVM
l)aTELOSEVMTESTNET
l*aLUKSO
l+aPANGOLIN
l,aCRAB
l-aPANGORO
l.aDARWINIA
l/aAIC
l0aETMP
l1aETMPTEST
l2aXDC
l3aTXDC
l4aCET
l5aTCET
l6aOP
l7aZYX
l8aBNB
l9aSYS
l:aONTOLOGYMAINNET
l;aEOS_LEGACY
l<aGO
l=aETC
l>aTETC
l?aMETC
l@aELLAISM
lAaTOKT
lBaOKT
lCaDBM
lDaSO1
lEaOKOV
lFaHSC
lGaCFXTEST
lHaDXC
lIaFNCY
lJaIDCHAIN
lKaDSC
lLaMIX
lMaSPOA
lNaPRIMUSCHAIN
lOaZENITH
lPaGENECHAIN
lQaJOC
lRaMETER
lSaMETERTEST
lTaLINQTO_DEVNET
lUaGTTEST
lVaGT
lWaNNW
lXaVIC
lYaVICT
lZaGAR_S0
l[aGAR_S1
l\aGAR_S2
l]aGAR_S3
l^aSDLT
l_aCAMDL
l`aBKC
laaBNBT
lbaSIX
lcaPOA
ldaGNO
leaETI
lfaTW3G
lgaWLC
lhaTKLC
liaDW3G
ljaVLX
lkaNTN
llaTT
lmaSHIBARIUMECOSYSTEM
lnaXPR
loaETL
lpaCOINBIT
lqaDEH
lraC2FLR
lsaDEBANK_TESTNET
ltaDEBANK_MAINNET
luaAUPTICK
lvaARCOLOGY
lwaENULS
lxaENULST
lyaREAL
lzaFUSE
l{aSPARK
l|aDWU
l}aOYCHAINTESTNET
l~aOYCHAINMAINNET
l aFETH
l  aHECO
l  aINNOVATOR
l  aTGRAM
l  aHSKT
l  aRLC
l  aALYXTESTNET
l  aDEAM
l  aMATIC
l  aDFIO_META_MAIN
l  aWOOP
l  aOPTEST
l  aDAX
l  aPHI
l  aSETH
l  aSHIMMEREVM
l  aSIXT
l  aRBN
l  aRBN_DEVNET
l  aRBN_TESTNET
l  aRBN_TGE
l  aTENET_TESTNET
l  aOBE
l  aPUPPYNET
l  aRBA
l  aRBAT
l  aEVA
l  aWALL_E
l  aTPHT
l  aPHT
l  aOMNI_TESTNET_164
l  aOMNI_TESTNET
l  aOMNI
l  aATOSHI
l  aAIOZ
l  aMANTA
l  aHOOSMARTCHAIN
l  aRESIL
l  aAME
l  aSEELE
l  aBMC
l  aBMCT
l  aFFG
l  aCEM
l  aTOKB
l  aOKB
l  aNEUTR
l  aBIT
l  aBTT
l  aAOX
l  aMOACTEST
l  aEDGELESS_TESTNET
l  aOBNB
l  aVCTEST
l  aVC
l  aUTX
l  aBTN
l  aEDI
l  aMAKALU
l  aB2HUB_MAINNET
l  aSHINARIUM
l  aSIN2
l  aSO1_OLD
l  aSEPSCAL
l  aASK
l  aB2_MAINNET
l  aVRD_TESTNET
l  aLA
l  aTLA
l  aFHE
l  aSDX
l  aPROTOJUMBO
l  aDEAMTEST
l  aBLAST
l  aPLGCHAIN
l  aEWT
l  aOAS
l  aFTM
l  aFRAXTAL
l  aKROMA
l  aHECOT
l  aSETM
l  aNEON
l  aSUR
l  aNEURA
l  aTNEURA
l  aDNEURA
l  aHPB
l  aEGONM
l  aLACHAIN
l  aFAI
l  aBPX
l  aZKSYNC_GOERLI
l  aZKTCRO
l  aBOBA
l  aORDERLY
l  aHEDERA_MAINNET
l  aHEDERA_TESTNET
l  aHEDERA_PREVIEWNET
l  aHEDERA_LOCALNET
l  aZKSYNC_SEPOLIA
l  aBOBAOPERA
l  aZKCANDY_SEPOLIA
l  aNCNT
l  aZKSATS_MAINNET
l  aLOVELY_TESTNET
l  aFURTHEON
l  aWYZ
l  aOMAX
l  aNCN
l  aFILECOIN
l  aKCS
l  aKCST
l  aCVM
l  aZKSYNC
l  aW3Q
l  aDFKTEST
l  aSDN
l  aTCRO
l  aTHETA_MAINNET
l  aTHETA_SAPPHIRE
l  aTHETA_AMBER
l  aTHETA_TESTNET
l  aPLS
l  aTCNT
l  aZKAMOEBA_TEST
l  aZKAMOEBA
l  aLISINSKI
l  aCAMDL_TESTNET
l  aNEAR
l  aNEAR_TESTNET
l  aN3
l  aHPN
l  aOZO_TST
l  aSYNDR_L3
l  aPEPE
l  aSX
l  aLATESTNET
l  aOGOR
l  aVRD
l  aPGN
l  aZEETH
l  aGSV
l  aBYC
l  aTEN_TESTNET
l  aSYNAPSE_SEPOLIA
l  aARZIO
l  aTAREA
l  aAREA
l  aRUPX
l  aCAMINO
l  aCOLUMBUS
l  aSYNDICATE_CHAIN_MAINNET
l  aAAC
l  aAACT
l  aGZ_MAINNET
l  aXT
l  aFIRE
l  aFXCORE
l  aCNDL
l  aOPTRUST
l  aPAW
l  aFLOW_TESTNET
l  aCLASS
l  aTAO
l  aDCT
l  aSYS_ROLLUX
l  aMETATIME
l  aFILENOVA
l  aMETIS_STARDUST
l  aASTR
l  aMACA
l  aTKAR
l  aTACA
l  aMETIS_GOERLI
l  aMESH_CHAIN_TESTNET
l  aVINE
l  aEIOB
l  aGLQ
l  aAVOCADO
l  aFLOW_PREVIEWNET
l  aSX_TESTNET
l  aACE
l  aKALICHAIN
l  aKALICHAINMAINNET
l  aULTRONSMARTCHAIN
l  aPIXIE_CHAIN_TESTNET
l  aLAOS
l  aJUNCA
l  aJUNCAT
l  aKAR
l  aREDSTONE
l  aSNS
l  aBCS
l  aTBCS
l  aFURY
l  aVRC
l  aSHIBARIUM
l  aLYC
l  aBLU
l  aLOVELY
l  aTCANTO
l  aVSCT
l  aSPAY
l  aFLOW_MAINNET
l  aQOM
l  aOPC
l  aCTH
l  aMAAL
l  aACA
l  aTAERO
l  aPETH
l  aRUPAYATESTNET
l  aLUCID
l  aHAIC
l  aPFTEST
l  aH1
l  aMEER
l  aFIRECHAN_ZKEVM
l  aBOC
l  aCLO
l  aTCLO
l  aRUNIC_TESTNET
l  aCDT
l  aTARA
l  aTARATEST
l  aZEETHDEV
l  aFSCMAINNET
l  aBNKEN
l  aDXT
l  aAMBROS
l  aWAN
l  aMAXI_TESTNET
l  aGAR_TEST_S0
l  aGAR_TEST_S1
l  aGAR_TEST_S2
l  aGAR_TEST_S3
l  aPF
l  aDBONE
l  aTAPROOT_MAINNET
l  aTFIRE
l  aMODESEP
l  aYDK
l  aTPLS
l  aT2BPLS
l  aT3PLS
l  aT4PLS
l  aMUNODE
l  aLYRA
l  aBTC20
l  aCCN
l  aHUYGENS
l  aASCRAEUS
l  aYETI
l  aSEXYTESTNET
l  aTOP_EVM
l  aMEMOCHAIN
l  aTOP
l  aELM
l  a_5IRE
l  aLN
l  aTWAN
l  aGTON
l  aBAOBAB
l  aTET
l  aT_EKTA
l  aTNEW
l  aEUN
l  aJUMBOSCAN
l  aEVC
l  aREBUS
l  aNEW
l  aSKU
l  aTCLV
l  aCLV
l  aTBTT
l  aCFX
l  aPRX
l  aBRONOS_TESTNET
l  aBRONOS_MAINNET
l  aSHIMMEREVM_TESTNET_DEPRECATED
l  aSHIMMEREVM_TESTNET_DEPRECATED_1072
l  aSHIMMEREVM_TESTNET
l  aIOTAEVM_TESTNET
l  aMINTARA_TESTNET
l  aMINTARA
l  aMETIS_ANDROMEDA
l  aHUMANS
l  aMOAC
l  aDYMENSION
l  aZKEVM
l  aTBLXQ
l  aBLXQ
l  aWEMIX
l  aTWEMIX
l  aB2HUB_TESTNET
l  aTCORE
l  aCORE
l  aDOGSM
l  aB2_TESTNET
l  aDFI
l  aDFI_T
l  aCHANGI
l  aLISK
l  aASART
l  aMATH
l  aTMATH
l  aPLEXCHAIN
l 	aAUOC
l 	aSHT
l 	aMOS
l 	aIORA
l 	aAVIS
l 	aWTT
l 	aSBC
l 	aPOPCAT
l 	aENTER
l 	aCYCLE
l 	aHYB
l 	aXZO
l 	aULTRONTESTNET
l 	aUTRONMAINNET
l 	aSTEP
l 	aARC
l 	aTARC
l 	aOM
l 	aDOGETHER
l 	aCICT
l
aHO
l
aMBEAM
l
aMRIVER
l
aMROCK_OLD
l
aMBASE
l
aMROCK
l
aSWTR
l
aBOBABEAM
l
aBOBABASE
l
aTDOS
l
aALYX
l
aAIA
l
aAIATESTNET
l
aGETH
l
aELST
l
aELSM
l
aBLITZ
l
aCIC
l
aZAFIC
l
aKLC
l
aASAR
l
aMUN
l
aZKEVMTEST
l  aTESTNET_ZKEVM_MANGO_PRE_AUDIT_UPGRADED
l  aRIK
l  aLAS
l  aTESTNET_ZKEVM_MANGO
l  aGIL
l  aMETATIMEISTANBUL
l  aCTEX
l  aVITRUVEO
l  aIGC
l  aCHAINX
l  aSHERPAX
l  aSHERPAXTESTNET
l  aBEAGLE
l  aTENET
l  aETINS
l  aCATE
l  aATH
l  aBTA
l  aLIQUICHAIN
l  aGOBI
l aMINTTEST
l aMINTSEPOLIATEST
l aLUDAN
l aANYTYPECHAIN
l aTBSI
l aTTBSI
l aDRC
l aPCM
l aREYA
l aTEAPARTY
l aGAUSS
l  aKERLEANO
l  aRANA
l  aCUBE
l  aCUBET
l  aRUBY
l  aTSF
l  aWBT
l  aGITSHOCKCHAIN
l  aLIGHTLINK_PHOENIX
l  aLIGHTLINK_PEGASUS
l  aBOYA
l  aSCN
l  aBITCI
l  aTBITCI
l  aMRK
l  aSCAL
l  aTRUBY
l  aUPBETH
l  aONUS_TESTNET
l  aDCHAIN_MAINNET
l  aTSEL
l  aDEXILLA
l  aSEL
l  aMTC
l  aTSCS
l  aSCS
l  aATLR
l  aREDE
l  aONUS_MAINNET
l  aEUNTEST
l  aSATOSHIE
l  aSATOSHIE_TESTNET
l  aEGEM
l  aHUBBLENET
l  aEKTA
l  aEDX
l  aKYOTO_TESTNET
l  aDC
l  aMILKADA
l  aMILKALGO
l  aCLOUDWALK_TESTNET
l  aCLOUDWALK_MAINNET
l  aNETZ
l  aTEL
l  aPMINT_DEV
l  aPMINT_TEST
l  aPMINT
l  aEDG
l  aEDGT
l  aTAYCAN_TESTNET
l  aSWAN
l  aRPG
l  aEDGELESS
l  aCFG
l  aNCFG
l  aPHA
l  aKIWI
l  aSHRAPTEST
l  aVANAR
l  aOTP
l  aSHRAPNEL
l  aSTOS_TESTNET
l  aSTOS_MAINNET
l  aMOVO
l  aQKA
l  aAIR
l  aALGL
l  aECO
l  aESP
l  aEXN
l  aCMCX
l  aMETAD
l  aMEU
l  aBIGSB_TESTNET
l  aBIGSB
l  aDFIO_META_TEST
l  aONENESS
l  aONENESS_TESTNET
l  aBOA
l  aFRA
l  aFINDORA_TESTNET
l  aFINDORA_FORGE
l  aMSN
l  aABNM
l  aBTC
l  aEVANESCO
l  aTKAVA
l  aKAVA
l  aVCHAIN
l  aKRST
l  aBOMB
l  aEBRO
l  aAREVIA
l  aSMA
l  aALT
l  aRSS3_TESTNET
l  aSMAM
l  aATLA
l  aOMNIA
l  aDEPRECATED_KROMA_SEPOLIA
l  aKROMA_SEPOLIA
l  aNZT
l  aBOMBT
l  aTCGV
l  aKARAK_MAINNET
l  aXODEX
l  aKOL
l  aZKEVM_TESTNET_CARDONA
l  aTHRC
l  aHRC
l  aU2U_NEBULAS
l  aKARAK_GOERLI
l  aFRAXTAL_TESTNET
l  aINEVM
l  aKTOC
l  aTPC
l  aPOCRNET
l  aREDLC
l  aEZCHAIN
l  aFUJI_EZCHAIN
l  aTWBT
l  aAPEXMAINNET
l  aTMORPH
l  aK_LAOS
l  aTXR
l  aTIME
l  aNANON
l  aHMORPH
l  aBOBAGOERLI
l  aELUX
l  aHYCHAIN
l  aXENON
l  aBTY
l  aCENNZ_R
l  aCENNZ_N
l  aCAU
l  a_3ULL
l  aORL
l  aREBUS_TESTNET
l  aBFC
l  aMOVE
l  aIMMU3
l  aVFI
l  aSAVM
l  aTSAVM
l  aFILECOIN_HYPERSPACE
l  aDUBX
l  aTESTDUBX
l  aDEBOUNCE_DEVNET
l  aZCRBEACH
l  aES_T
l  aW3Q_G
l  aPRB
l  aEVOM
l  aSCAIT
l  aPRBTESTNET
l  aJFIN
l  aPANDO_MAINNET
l  aPANDO_TESTNET
l  aBTNX
l  aBTCM
l  aISLAMI
l  aJOULEVERSE
l  aBTX
l  aEMPIRE
l  aSPCT
l  aSPCM
l  aXPLATEST
l  aCSB
l  aASTRZK
l  aALV
l  aTTANGLE
l  aFIRECHAIN_ZKEVM_TESTNET
l  aKALYMAINNET
l  aKALYTESTNET
l  aDRAC
l  aDOST
l  aDYNO
l  aTDYNO
l  aAPEXSEP
l  aYCC
l  aOZO
l  aPERIUM
l  aTFTM
l  aX1_FASTNET
l  aGANTESTNET
l  aBOBAOPERATESTNET
l  aNAHMII3MAINNET
l  aNAHMII3TESTNET
l  aMUSTER
l  aOASIS
l  aBNIT
l  aBNIM
l  aAIOZ_TESTNET
l  aHUMANS_TESTNET
l  aTPBXT
l  aCROSSFI_TESTNET
l  aPHIV1
l  aMERLIN_MAINNET
l  aLUKSO_TESTNET
l  aLISKSEP
l !aNEXI
l !aNEXIV2
l !aBOBAFUJITESTNET
l !aBEAM
l "aCREDITEDGE
l "aHTML
l "aORDERLYL2
l #aEMONEY
l $aVERY
l $aGOLD
l $aIOTEX_MAINNET
l $aIOTEX_TESTNET
l %aTESTMEV
l %aTBXN
l &aGC
l &aTXVM
l &aXVM
l 'aBXN
l 'aMANTLE
l 'aMANTLE_TESTNET
l 'aTREASURENET
l 'aMNT_SEP
l 'aTNTEST
l 'aONIGIRI
l 'aNOLLIE_TESTNET
l 'aSYNDICATE_CHAIN_TESTNET
l 'aSYNDICATE_CHAIN_FRAME
l 'aSIC_TESTNET
l 'aCOORDINAPE_TESTNET
l 'aCHARMVERSE_TESTNET
l 'aSUPERLOYALTY_TESTNET
l 'aAZRA_TESTNET
l (aFTN
l (aSLN
l (aTLC
l (aES
l (aHMND
l )a_OLD_FIRE
l )aUZMI
l )aTOPTRUST
l )aTTRN
l *aEDEXA
l *aEGAX
l +aVEX
l +aNAHMII
l +aNAHMIITESTNET
l +aCVERSE
l +aOBNBT
l +aARCTURUS_TESTNET
l +aARCT
l ,aQIE
l ,aTFILENOVA
l ,aTANGO
l ,aTSYS
l ,aHIK
l ,aSATST
l -aGGUI
l -aTANGLE
l -aONTOLOGYTESTNET
l -aRBD
l .aBOUNCEBIT_TESTNET
l .aBOUNCEBIT_MAINNET
l /aTRESTEST
l /aTRESMAIN
l /aCASCADIA
l /aUPTN_TEST
l /aUPTN
l 1aEAURA
l 1aDGS
l 2aPEERPAY
l 3aSRC_TEST
l 3aFOX
l 3aPIXIE_CHAIN
l 4aLATESTT
l 4aCYBA
l 4aTCYBA
l 4aIRIS
l 4aPAXB
l 4aCOMPVERSE
l 5aSTANDM
l 6aTOMBCHAIN
l 6aPSC
l 6aZETACHAIN_MAINNET
l 6aZETACHAIN_ATHENS
l 6aBSTC
l 6aELLA
l 7aPLANQ
l 7aPLANQ_ATLAS_TESTNET
l 7aNUME
l 7aHTH
l 8aBITROCK
l 9aKLY
l 9aEON
l 9aSHYFT
l :aRABA
l :aMEV
l ;aCYETH
l ;aTADIL
l ;aADIL
l ;aTRN_MAINNET
l ;aTRN_PORCINI
l <aCANTO
l <aTESTNETCANTO
l <aTBITROCK
l <aGDCC
l <aRISEOFTHEWARBOTSTESTNET
l <aORE
l <aOEX
l =aMAAL_TEST
l =aTSCAS
l =aKINTOMAINNET
l =aARD
l =aDTBX
l >aDOS
l >aTELEPORT
l >aTELEPORT_TESTNET
l >aMDGL
l >aKARAK_SEPOLIA
l ?aLIBERTY10
l ?aLIBERTY20
l ?aSPHINX10
l ?aBITCOIN
l ?aE_DOLLAR
l ?aSTREAMUX
l ?aMEERTEST
l ?aMEERMIX
l ?aMEERPRIV
l ?aAMANA
l ?aFLANA
l ?aMIZANA
l ?aTBOC
l @aTQF
l @aTTQF
l @aCYPRESS
l @aBTON
l @aKORTHO
l AaFUCK
l BaBASE
l CaTOKI
l CaTOKI_TESTNET
l CaHELA
l DaOLO
l DaTOLO
l DaSTOR
l DaTSTOR
l DaALPH
l DaTMY
l DaIOTAEVM
l EaMARO
l EaSUPERLUMIO
l EaUNQ
l EaQTZ
l EaOPL
l EaSPH
l EaXANACHAIN
l EaVSC
l EaTORE
l EaMMT
l EaJBC
l FaGMMT
l FaBERG
l FaEVMOS_TESTNET
l FaEVMOS
l FaSHIDOTESTNET
l FaSHIDO
l FaBRB
l FaNEXATESTNET
l FaNEXA
l GaGENEC
l Ga_OLD_TFIRE
l HaCOF
l HaDOGST
l IaDELASEP
l IaMTHN
l JaTRPG
l JaQETTEST
l JaTESTNEON
l KaMAINNETDEV
l LaBOBABNBTESTNET
l LaNETZT
l LaPN
l LaCARBON
l LaCARBON_TESTNET
l LaTIMP
l LaIMP
l MaDOGELAYER
l MaLRS
l MaSPENT
l MaTMIND
l MaCOMBO_MAINNET
l NaAGNG
l NaMIND
l NaALT_TESTNET
l NaZTC
l NaMYN
l NaSMARTBCH
l NaSMARTBCHTEST
l NaGON
l NaJOCT
l NaSJ
l NaGEN
l OaCHI
l OaPWR
l PaAA
l PaAAT
l Pa_0XT
l QaTWLC
l RaJADE
l RaSNOW
l TaCCP
l UaQUADRANS
l UaQUADRANSTESTNET
l VaASTRA
l VaWAGMI
l VaASTRA_TESTNET
l VaHBIT
l WaSC20
l WaISLM
l YaSHYFTT
l YaBEVM
l YaBEVM_TEST
l ZaSRDXT
l \aSAN
l \aARIANEE
l ]aSATS
l ]aATR
l ^aTZERO
l ^aZERO
l ^aBRC
l `aFIBO
l `aBLGCHAIN
l `aSTEPTEST
l baRSS3
l caTRIK
l daTQNET
l eaSPS
l gaCREDIT
l haBEAM_TESTNET
l haIMX
l haPHOENIX
l haMASA
l iaIMX_TESTNET
l jaKNB
l kaSUS
l maSPS_TEST
l oaEVO
l oaVITRUVEO_TEST
l taHMND_T5
l uaIMX_DEVNET
l yaLOOP
l yaTRUSTTESTNET
l yaEOS_TESTNET
l }aMTT
l }aMTTTEST
l   aGENESYS
l   aNYANCAT
l   aAIRDAO
l   aTIVAR
l   aHOLESKY
l   aREDSTONE_HOLESKY
l   aGARNET
l   aG8CM
l   aECLIPSE
l   aPCT
l   aKONET
l   aEOS
l   aZKST
l   aSTN
l   aPOM
l   aG8CT
l   aUNREAL_OLD
l   aUNREAL
l   aMXCZKEVM
l   aTITAN_TKX
l   aTITAN_TKX_TESTNET
l   aHMV
l   aDCSMS
l   aMGT
l   aLBRY
l   aBTCIX
l   aCAMELARK
l   aCLOTESTNET
l   aP12
l   aJONO11
l   aC4EI
l   aAAH
l   aCENNZ_A
l   aOMC
l   aONF
l   aSFL
l   aAIRDAO_TEST
l   aNAUTCHAIN
l   aGOLDX_TESTNET
l   aMAPO
l   aABNT
l   aOPSIDE
l   aSAPPHIRE
l   aSAPPHIRE_TESTNET
l   aDREYERX
l   aDREYERX_TESTNET
l   aBLASTT
l   aWEB
l   aMINTME
l   aLILA
l   aTALV
l   aGOLDT
l   aBKCT
l   aFRM
l   aHTZ
l   aOAC
l   aKLAOSNOVA
l   aNANON_TESTNET
l   aZEROONEMAI
l   aVIZING_TESTNET
l   aVIZING
l   aOBGOR
l   aBOBASEPOLIA
l   aHYCHAIN_TESTNET
l   aTKEC
l   aMCHV
l   aPIECE
l   aMIYOU
l   aCERI
l   aMOVELEG
l   aMOVEDEV
l   aMOVETEST
l   aESN
l   aCLDTX
l   aCLD
l   aGOT
l   aTMTHN
l   aFILECOIN_WALLABY
l   aW3GAMEZ
l   aBRISE
l   aFSN
l   aZIL
l   aZIL_ISOLATED_SERVER
l   aZIL_TESTNET
l   aCLOUDVERSE
l   aAVS
l   aZIL_DEVNET
l   aZQ2_DEVNET
l   aMODE
l   aJ2O
l   wQl   aQ_TESTNET
l   aCMRPG
l   aTTRPG
l   aNRG
l   aOHO
l   aOX_BETA
l   aPC
l   aARB1
l   aARB_NOVA
l   aCELO
l   aEMERALD_TESTNET
l   aEMERALD
l   aGOLDX
l   aZKFAIR_MAINNET
l   aGST
l   aKETH
l   aAVAETH
l   aHEMI
l   aFUJI
l   aAVAX
l   aBOBAAVAX
l   aZKFAIR_TESTNET
l   aFREN
l   aQTM
l   aALFA
l   aAUTOBAHNNETWORK
l   aSWP
l   aDEE
l   aTFSN
l   aREI
l   aFLORIPA
l   aTBFC
l   aSTORK
l   aTNRG
l   aLOE
l   aYVM
l   aYVT
l   aTGTON
l   aLUMOZ_TESTNET
l   aSRDXM
l   aETN_MAINNET
l   aDOID
l   aDODOCHAIN
l   aDFK
l   aISLMT
l   aTORONETTESTNET
l   aPTON
l   aTETH
l   aREICHAIN
l   aTREI
l   aLAMBDA
l   aBOBABNB
l   aTESTNETZER
l   aVELO
l   aDOIDTESTNET
l   aTSYS_ROLLUX
l   aSEPPGN
l   aLINEA_GOERLI
l   aLINEA_SEPOLIA
l   aLINEA
l   aGCODE
l   aTKM_TEST0
l   aTKM_TEST1
l   aTKM_TEST2
l   aTKM_TEST103
l   aBOB
l   aKEC
l   aAIUM_DEV
l   aETICA
l   aDOKEN
l   aOPTOPIA_TESTNET
l   aOPTOPIA
l   aBKLV
l   aMTV
l   aECS
l   aECS_TESTNET
l   aSRC
l   aJANUSNETWORK_TESTNET
l   aMCL
l   aCOSMIC
l   aDM2
l   aCNDR
l   aTKM0
l   aTKM1
l   aTKM2
l   aTKM103
l   aPOP_APEX
l   aGUAPX
l   aCKB
l   aGW_TESTNET_V1
l   aGW_MAINNET_V1
l   aCAGA
l   aGROKCHAIN
l   aICBT
l   aICBX
l   aVT
l   aMVM
l   aRESIN
l   aBORACHAIN
l   aFNC
l   aVSCM
l   aTORONET
l   aFIRENZE
l   aDFLY
l   aAMPLIFY
l   aBULLETIN
l   aCONDUIT
l   aVANGUARD
l   aSTANDT
l   aMATICMUM
l   aPOLYGONAMOY
l   aBERACHAINARTIO
l   aHZC
l   aNORDEK
l   aAMANATEST
l   aAMANAMIX
l   aAMANAPRIV
l   aFLANATEST
l   aFLANAMIX
l   aFLANAPRIV
l   aMIZANATEST
l   aMIZANAMIX
l   aMIZANAPRIV
l   aBLASTMAINNET
l   aQNET
l   aTSLN
l   aZEDX
l   aBASEGOR
l   aBASESEP
l   aAERIE
l   aCYBER
l   aNAUTTEST
l   aUNIT0_TESTNET
l   aUNIT0_STAGENET
l   aCHZ
l   aIVAR
l   aDHOBYGHAUT
l   aBVHL
l   aCAMP
l   aNAUT
l   aMETADAP
l   aCOMBO_TESTNET
l   aLAMBDA_TESTNET
l   aTLILA
l   aMANTIS
l   aBOBABNBOLD
l   aELT
l   aUSCTEST
l   aUSC
l   aQKC_R
l   aQKC_S0
l   aQKC_S1
l   aQKC_S2
l   aQKC_S3
l   aQKC_S4
l   aQKC_S5
l   aQKC_S6
l   aQKC_S7
l   aVECHAIN
l   aVECHAIN_TESTNET
l   aCHI1
l   aSTABILITYPROTOCOL
l   aCTCTEST
l   aCRFI
l   aMASATEST
l   aCAS
l   aSTRATIS
l   aBRO
l   aQKC_D_R
l   aQKC_D_S0
l   aQKC_D_S1
l   aQKC_D_S2
l   aQKC_D_S3
l   aQKC_D_S4
l   aQKC_D_S5
l   aQKC_D_S6
l   aQKC_D_S7
l   aTESTSBR
l   aSBR
l   aRE_AL
l   aMETAO
l   aMETADAP_T
l   aDADIL
l   aETLT
l   aDIONE
l   aETND
l   aMAG
l   aICPLAZA
l  	aPLAYFI
l
aTKO_MAINNET
l
aTAIKO_A2
l
aTAIKO_L2
l
aTAIKO_L3
l
aTKO_JOLNIR
l
aTKO_KATLA
l
aTKO_HEKLA
l   aBDCC
l   aCONDOR
l   aFHET
l   aFAIT
l   aMILKTADA
l   aMILKTALGO
l   aAKA
l   aBTRT
l   aBTR
l   aALAYA
l   aALAYADEV
l   aMYTH
l   aTDSC
l   aX1_DEVNET
l   aYMTECH_BESU
l   aTWL_JELLIE
l   aX1_TESTNET
l   aAURORIA
l   aATLAS
l   aPLATON
l  aMAS
l  aREAP
l  aREAP_TESTNET
l  aHDX
l  aDEEPL
l  aTDEEPL
l  aTAFECO
l  aCONET_SEBOLIA
l  aCONET_HOLESKY
l   aHSKTEST
l   aHYM
l   aATS
l   aATSTAU
l   aSAAKURU_TESTNET
l   aCMP_MAINNET
l   aGZ_TESTNET
l   aEGONT
l   aSOCHAIN
l   aZILLSEP
l   aSAHARATEST
l   aFILECOIN_CALIBRATION
l   aPAREX
l   aBGBC_TESTNET
l   aTC
l   aBGBC
l   aAVST
l   aN3_TEST
l   aOONETEST
l   aOONEDEV
l   aSPARTA
l   aOLYMPUS
l   aUPCHAIN_TESTNET
l   aUPCHAIN_MAINNET
l   aBITFINITY
l   aDS2
l   aHAP_TESTNET
l   aMETAL
l   aTAHOE
l   aTPBXM
l   aAIET
l   aKEK
l   aTKEK
l   aALTERIUM
l   aARB_RINKEBY
l   aARB_GOERLI
l   aARB_SEP
l   aFASTEXTESTNET
l   aMARKR_GO
l   aDEXALOT_TESTNET
l   aDEXALOT
l   aSYNDR
l   aWLKT
l   aPSEP
l   aULTRAPRO
l   aOC
l   aCMP
l   aDIS
l   aDOCOIN
l   aSCR_SEPOLIA
l   aSCR
l   aSCR_ALPHA
l   aSCR_PREALPHA
l   aSHI
l   aBESC
l  !aECLIPSET
l  %aHYP
l  'aBRNKC
l  'aALL
l  (aXAI
l  (aVPIONEER
l  (aHELA_TESTNET
l  )aWONCHAIN
l  *aGALADRIEL_DEVNET
l  +aTILTYARDMAINNET
l  +aSEI_DEVNET
l  -aHEMI_SEP
l  -aBRNKCTEST
l  .aMIEXS
l  /aMDLRM
l  0aOCTA
l  1aBIZT_TESTNET
l  1aZKLINK_NOVA
l  1aZKLINK_NOVA_SEPOLIA
l  1aZKLINK_NOVA_GOERLI
l  2aCURVEM
l  3aBLOQS4GOOD
l  4aDODAO
l  5aBLX
l  6aREXX
l  6aVISION
l  6aPSC_S0
l  7aPSC_T_S0
l  7aRIA_DEV
l  8aPSC_D_S0
l  8aPSC_D_S1
l  8aTFNCY
l  :aJONO12
l  :aELV
l  <aECROX
l  =aAMC
l  CaNMTTEST
l  DaTILTYARD
l  LaAZKTN
l  PaETHO
l  PaXERO
l  QaKINTSUGI
l  QaKILN
l  QaZHEJIANG
l  baALBERIO
l  iaTDD
l  {aDBK
l    aPLIAN_MAINNET
l    aPLATONDEV
l    aPLATONDEV2
l    aDPU
l    aSAHARA
l    aFILECOIN_BUTTERFLY
l    aMANTATESTNET
l    aMANTASEPOLIATESTNET
l    aALT_ZEROGAS
l    aWORLDSCAL
l    aMXCDISCONTINUED
l    aMXC
l    aETN_TESTNET
l    aKREACT
l    aIMVERSED
l    aIMVERSED_TESTNET
l    aAZKYT
l    aSAFEMAINNET
l    aSAFETESTNET
l    aSAAKURU
l    aVSL
l    aTQOM
l    aMUSIC
l    aZORA
l    aPLIAN_MAINNET_L2
l    aHOKUM
l    aHAP
l    aQUARIX_TESTNET
l    aQUARIX
l    aXCAP
l    aMILV
l    aPLIAN_TESTNET_L2
l    aSVRNM
l    aSEP
l    aOPSEP
l    aTPEP
l    aANDUSCHAIN_MAINNET
l    aPLIAN_TESTNET
l    aTLAMBDA
l    aILT
l   	aSTABILITYTESTNET
l   	aSPECTRUM
l   	aQKI
l   	aPG
l   	aDBKSE
l   	aHOKUM_TESTNET
l
aXLON
l    aEXLVOLTA
l    aEXL
l   aA8
l   aAUXI
l   aFLA
l    aFILECOIN_LOCAL
l    aJOYS
l    aNEBULA_TESTNET
l    aKCHAIN
l    aMAIS
l    aAQUA
l    aBAKERLOO_0
l    aBAKERLOO_01
l    aBAKERLOO_02
l    aPICCADILLY_0
l    aPICCADILLY_01
l    aPICCADILLY_02
l    aFRAMETEST
l   %aHETH
l   *aTEAM
l   ,aPOLYGON_BLACKBERRY
l   /aTOYS
l   5aCYSEP
l   :aOPCELESTIA_RASPBERRY
l   LaPLUME_TESTNET
l   PaBLASTSEPOLIA
l   [aGTH
l   iaKANAZAWA
l   taNEONEVM_DEVNET
l   taNEONEVM_MAINNET
l   taNEONEVM_TESTNET
l     aRAZOR
l     aONELEDGER
l     aMELD
l     aDEPRECTED_CALYPSO_TESTNET
l     aTGTH
l     aDEPRECATED_EUROPA_TESTNET
l     aDGTH
l     aDEPRECATED_NEBULA_TESTNET
l     aDEGEN_CHAIN
l     aANCIENT8
l     aPTCE
l     aPOLYTECH
l     aCALYPSO_TESTNET
l     aZSEP
l     aTITAN_TESTNET
l     aIPOS
l     aCYB
l     aHUMAN_MAINNET
l     aAURORA
l     aAURORA_TESTNET
l     aAURORA_BETANET
l     aPOWERGOLD
l     aTITAN_MAINNET
l     aCHAOS_TENET
l     aRARI_MAINNET
l     aRPTR
l     aEUROPA_TESTNET
l     aNEBULA_MAINNET
l     aDEPRECATED_TITAN_TESTNET
l     aCALYPSO_MAINNET
l     aHMY_S0
l     aHMY_S1
l     aHMY_S2
l     aHMY_S3
l     aHMY_B_S0
l     aHMY_B_S1
l     aHMY_PS_S0
l     aHMY_PS_S1
l     aKKRT_SEPOLIA
l     aRARI_TESTNET
l     aHOP
l     aEUROPA
g       aA8OLD
g       aPIRL
g       aFRANKENSTEIN
g       aTPALM
g       aPALM
g      aGS_ETH
g       aXAITESTNET
g )   2aARB_BLUEBERRY
g 1     aKKRT_SEPOLIA_DEPRECATED
g 3     aALPHABET
g \   CaNTT
g \   CaNTT_HARADEV
g        aZENIQ
g        aIPDC
g        aMOLE
g     aGW_TESTNET_V1_DEPRECATED
g   M     aDCHAINT
a__orig_bases__
ueth_typing\networks.py
u<module eth_typing.networks>
T a__class__

a__spec__
.eth_utils.abi
SH
a_get_tuple_type_str_and_dims
get
T atype

cast
aIterable
aABIComponent
components
count
T w[acopy
u[]
type
itertools
repeat
abc
aMapping
is_list_like
uExpected non-string sequence for "
T atype

u" component type: got

Aligns the values of any mapping at any level of nesting in ``normalized_arg``
ccording to the layout of the corresponding abi spec.
normalized_arg
name
u<genexpr>
u_align_abi_input.<locals>.<genexpr>
a_align_abi_input
re
compile
T u^(tuple)((\[([1-9]\d* )?])*)??$
match
group
T l T l u
Takes a JSON ABI type string.  For tuple type strings, returns the separated
prefix and array dimension parts.  For all other strings, returns ``None``.
function
uOutputs only supported for ABI type `function`. Provided ABI type was `
u` and outputs were `
T aoutputs
u`.
fallback
receive
uInputs not supported for function types `fallback` or `receive`. Provided ABI type was `
u` with inputs `
T ainputs
uThe 'type' must be a string, but got
u of type
startswith
T atuple
w,:l nnw(w)u
Extract argument types from a function or event ABI parameter.
With tuple argument types, return a Tuple of each type.
Returns the param if `abi` is an instance of str or another non-tuple
type.
:param abi: A Function or Event ABI component or a string with type info.
:type abi: `Union[ABIComponent, Dict[str, Any], str]`
:return: Type(s) for the function or event ABI param.
:rtype: `str`
.. doctest::
>>> from eth_utils.abi import collapse_if_tuple
>>> abi = {
...   'components': [
...     {'name': 'anAddress', 'type': 'address'},
...     {'name': 'anInt', 'type': 'uint256'},
...     {'name': 'someBytes', 'type': 'bytes'},
...   ],
...   'type': 'tuple',
... }
>>> collapse_if_tuple(abi)
'(address,uint256,bytes)'
collapse_if_tuple
ucollapse_if_tuple.<locals>.<genexpr>
u{name}({input_types})
T aname
input_types
constructor
get_abi_input_types

Returns a string signature representation of the function or event ABI
nd arguments.
Signatures consist of the name followed by a list of arguments.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:return: Stringified ABI signature
:rtype: `str`
.. doctest::
>>> from eth_utils import abi_to_signature
>>> abi_element = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'name': 'f',
...   'outputs': [],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> abi_to_signature(abi_element)
'f(uint256)'
event
error

Get one or more function and event ABIs by name.
:param abi_name: Name of the function, event or error.
:type abi_name: `str`
:param contract_abi: Contract ABI.
:type contract_abi: `ABI`
:return: Function or event ABIs with matching name.
:rtype: `Sequence[ABIElement]`
.. doctest::
>>> from eth_utils.abi import filter_abi_by_name
>>> abi = [
...     {
...         "constant": False,
...         "inputs": [],
...         "name": "func_1",
...         "outputs": [],
...         "type": "function",
...     },
...     {
...         "constant": False,
...         "inputs": [
...             {"name": "a", "type": "uint256"},
...         ],
...         "name": "func_2",
...         "outputs": [],
...         "type": "function",
...     },
...     {
...         "constant": False,
...         "inputs": [
...             {"name": "a", "type": "uint256"},
...             {"name": "b", "type": "uint256"},
...         ],
...         "name": "func_3",
...         "outputs": [],
...         "type": "function",
...     },
...     {
...         "constant": False,
...         "inputs": [
...             {"name": "a", "type": "uint256"},
...             {"name": "b", "type": "uint256"},
...             {"name": "c", "type": "uint256"},
...         ],
...         "name": "func_4",
...         "outputs": [],
...         "type": "function",
...     },
... ]
>>> filter_abi_by_name("func_1", abi)
[{'constant': False, 'inputs': [], 'name': 'func_1', 'outputs': [], 'type': 'function'}]
aLiteral
uUnsupported ABI type:

Return a list of each ``ABIElement`` that is of type ``abi_type``.
For mypy, function overloads ensures the correct type is returned based on the
``abi_type``. For example, if ``abi_type`` is "function", the return type will be
``Sequence[ABIFunction]``.
:param abi_type: Type of ABI element to filter by.
:type abi_type: `str`
:param contract_abi: Contract ABI.
:type contract_abi: `ABI`
:return: List of ABI elements of the specified type.
:rtype: `Sequence[Union[ABIFunction, ABIConstructor, ABIFallback, ABIReceive, ABIEvent, ABIError]]`
.. doctest::
>>> from eth_utils import filter_abi_by_type
>>> abi = [
...   {"type": "function", "name": "myFunction", "inputs": [], "outputs": []},
...   {"type": "function", "name": "myFunction2", "inputs": [], "outputs": []},
...   {"type": "event", "name": "MyEvent", "inputs": []}
... ]
>>> filter_abi_by_type("function", abi)
[{'type': 'function', 'name': 'myFunction', 'inputs': [], 'outputs': []}, {'type': 'function', 'name': 'myFunction2', 'inputs': [], 'outputs': []}]
filter_abi_by_type

Return interfaces for each function in the contract ABI.
:param contract_abi: Contract ABI.
:type contract_abi: `ABI`
:return: List of ABIs for each function interface.
:rtype: `Sequence[ABIFunction]`
.. doctest::
>>> from eth_utils import get_all_function_abis
>>> contract_abi = [
...   {"type": "function", "name": "myFunction", "inputs": [], "outputs": []},
...   {"type": "function", "name": "myFunction2", "inputs": [], "outputs": []},
...   {"type": "event", "name": "MyEvent", "inputs": []}
... ]
>>> get_all_function_abis(contract_abi)
[{'type': 'function', 'name': 'myFunction', 'inputs': [], 'outputs': []}, {'type': 'function', 'name': 'myFunction2', 'inputs': [], 'outputs': []}]

Return interfaces for each event in the contract ABI.
:param contract_abi: Contract ABI.
:type contract_abi: `ABI`
:return: List of ABIs for each event interface.
:rtype: `Sequence[ABIEvent]`
.. doctest::
>>> from eth_utils import get_all_event_abis
>>> contract_abi = [
...   {"type": "function", "name": "myFunction", "inputs": [], "outputs": []},
...   {"type": "function", "name": "myFunction2", "inputs": [], "outputs": []},
...   {"type": "event", "name": "MyEvent", "inputs": []}
... ]
>>> get_all_event_abis(contract_abi)
[{'type': 'event', 'name': 'MyEvent', 'inputs': []}]
a_raise_if_fallback_or_receive_abi
aSequence
inputs
uIncorrect argument count. Expected '
u', got '
u'.
aTuple
aAny
intersection
T aname
u() got multiple values for argument(s) '
u,
sorted
difference
u{} got unexpected keyword argument(s) '{}'.
u()
uType: '
w'achain
items
u<lambda>
uget_normalized_abi_inputs.<locals>.<lambda>
T akey

Flattens positional args (``args``) and keyword args (``kwargs``) into a Tuple and
uses the ``abi_element`` for validation.
Checks to ensure that the correct number of args were given, no duplicate args were
given, and no unknown args were given.  Returns a list of argument values aligned
to the order of inputs defined in ``abi_element``.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:param args: Positional arguments for the function.
:type args: `Optional[Sequence[Any]]`
:param kwargs: Keyword arguments for the function.
:type kwargs: `Optional[Dict[str, Any]]`
:return: Arguments list.
:rtype: `Tuple[Any, ...]`
.. doctest::
>>> from eth_utils import get_normalized_abi_inputs
>>> abi = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 'name',
...       'type': 'string'
...     },
...     {
...       'name': 's',
...       'type': 'uint256'
...     },
...     {
...       'name': 't',
...       'components': [
...         {'name': 'anAddress', 'type': 'address'},
...         {'name': 'anInt', 'type': 'uint256'},
...         {'name': 'someBytes', 'type': 'bytes'},
...       ],
...       'type': 'tuple'
...     }
...   ],
...   'name': 'f',
...   'outputs': [],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> get_normalized_abi_inputs(
...   abi, *('myName', 123), **{'t': ('0x1', 1, b'\x01')}
... )
('myName', 123, ('0x1', 1, b'\x01'))
uget_normalized_abi_inputs.<locals>.<genexpr>
sorted_arg_names
index
normalized_args

Returns a pair of nested Tuples containing a list of types and a list of input
values sorted by the order specified by the ``abi``.
``normalized_args`` can be obtained by using
:py:meth:`eth_utils.abi.get_normalized_abi_inputs`, which returns nested mappings
or sequences corresponding to tuple-encoded values in ``abi``.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:param normalized_args: Normalized arguments for the function.
:type normalized_args: `Union[Tuple[Any, ...], Mapping[Any, Any]]`
:return: Tuple of types and aligned arguments.
:rtype: `Tuple[Tuple[str, ...], Tuple[Any, ...]]`
.. doctest::
>>> from eth_utils import get_aligned_abi_inputs
>>> abi = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 'name',
...       'type': 'string'
...     },
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'name': 'f',
...   'outputs': [],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> get_aligned_abi_inputs(abi, ('myName', 123))
(('string', 'uint256'), ('myName', 123))
uget_aligned_abi_inputs.<locals>.<genexpr>

Return names for each input from the function or event ABI.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:return: Names for each input in the function or event ABI.
:rtype: `List[str]`
.. doctest::
>>> from eth_utils import get_abi_input_names
>>> abi = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'name': 'f',
...   'outputs': [],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> get_abi_input_names(abi)
['s']

Return types for each input from the function or event ABI.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:return: Types for each input in the function or event ABI.
:rtype: `List[str]`
.. doctest::
>>> from eth_utils import get_abi_input_types
>>> abi = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'name': 'f',
...   'outputs': [],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> get_abi_input_types(abi)
['uint256']
a_raise_if_not_function_abi
outputs

Return names for each output from the ABI element.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:return: Names for each function output in the function ABI.
:rtype: `List[str]`
.. doctest::
>>> from eth_utils import get_abi_output_names
>>> abi = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'name': 'f',
...   'outputs': [
...     {
...       'name': 'name',
...       'type': 'string'
...     },
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> get_abi_output_names(abi)
['name', 's']

Return types for each output from the function ABI.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:return: Types for each function output in the function ABI.
:rtype: `List[str]`
.. doctest::
>>> from eth_utils import get_abi_output_types
>>> abi = {
...   'constant': False,
...   'inputs': [
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'name': 'f',
...   'outputs': [
...     {
...       'name': 'name',
...       'type': 'string'
...     },
...     {
...       'name': 's',
...       'type': 'uint256'
...     }
...   ],
...   'payable': False,
...   'stateMutability': 'nonpayable',
...   'type': 'function'
... }
>>> get_abi_output_types(abi)
['string', 'uint256']
keccak
replace
T w u
T atext
:nl nu
Return the 4-byte function selector from a function signature string.
:param function_signature: String representation of the function name and arguments.
:type function_signature: `str`
:return: 4-byte function selector.
:rtype: `bytes`
.. doctest::
>>> from eth_utils import function_signature_to_4byte_selector
>>> function_signature_to_4byte_selector('myFunction()')
b'\xc3x\n:'
abi_to_signature
function_signature_to_4byte_selector

Return the 4-byte function signature of the provided function ABI.
:param abi_element: ABI element.
:type abi_element: `ABIElement`
:return: 4-byte function signature.
:rtype: `bytes`
.. doctest::
>>> from eth_utils import function_abi_to_4byte_selector
>>> abi_element = {
...   'type': 'function',
...   'name': 'myFunction',
...   'inputs': [],
...   'outputs': []
... }
>>> function_abi_to_4byte_selector(abi_element)
b'\xc3x\n:'

Return the 32-byte keccak signature of the log topic for an event signature.
:param event_signature: String representation of the event name and arguments.
:type event_signature: `str`
:return: Log topic bytes.
:rtype: `bytes`
.. doctest::
>>> from eth_utils import event_signature_to_log_topic
>>> event_signature_to_log_topic('MyEvent()')
b'M\xbf\xb6\x8bC\xdd\xdf\xa1+Q\xeb\xe9\x9a\xb8\xfd\xedb\x0f\x9a\n\xc21B\x87\x9aO\x19*\x1byR\xd2'
event_signature_to_log_topic

Return the 32-byte keccak signature of the log topic from an event ABI.
:param event_abi: Event ABI.
:type event_abi: `ABIEvent`
:return: Log topic bytes.
:rtype: `bytes`
.. doctest::
>>> from eth_utils import event_abi_to_log_topic
>>> abi = {
...   'type': 'event',
...   'anonymous': False,
...   'name': 'MyEvent',
...   'inputs': []
... }
>>> event_abi_to_log_topic(abi)
b'M\xbf\xb6\x8bC\xdd\xdf\xa1+Q\xeb\xe9\x9a\xb8\xfd\xedb\x0f\x9a\n\xc21B\x87\x9aO\x19*\x1byR\xd2'
a__doc__
a__file__
origin
has_location
a__cached__
collections
T aabc
aDict
aList
aOptional
aUnion
overload
eth_typing
T	aABI
aABIComponent
aABIConstructor
aABIElement
aABIError
aABIEvent
aABIFallback
aABIFunction
aABIReceive
aABI
aABIConstructor
aABIElement
aABIError
aABIEvent
aABIFallback
aABIFunction
aABIReceive
ueth_utils.types
T ais_list_like
crypto
T akeccak
arg_abi
return
wsaabi_element
abi
abi_name
contract_abi
filter_abi_by_name
abi_type
T afunction
constructor
fallback
receive
event
error
get_all_function_abis
get_all_event_abis
args
kwargs
get_normalized_abi_inputs
T Ostr
Q
get_aligned_abi_inputs
get_abi_input_names
get_abi_output_names
get_abi_output_types
D afunction_signature
return
Ostr
Obytes
function_abi_to_4byte_selector
D aevent_signature
return
Ostr
Obytes
event_abi
event_abi_to_log_topic
ueth_utils\abi.py
T a.0
abi
normalized_arg
T a.0
sub_abi
sub_arg
T a.0
wcT a.0
abi
T a.0
abi
arg
T a.0
abi
normalized_args
T a.0
arg_abi
T akv
sorted_arg_names
T asorted_arg_names
u<module eth_utils.abi>
T
arg_abi
normalized_arg
tuple_parts
tuple_prefix
tuple_dims
sub_abis
num_dims
new_abi
aligned_arg
typing
T wsatuple_type_str_re
match
tuple_prefix
tuple_dims
T aabi_element
T aabi_element
signature
abi_type
fn_name
T aabi
element_type
delimited
array_dim
collapsed
T aevent_abi
event_signature
T aevent_signature
T aabi_name
contract_abi
T aabi_type
contract_abi
T aabi_element
function_signature
T afunction_signature
T aabi_element
normalized_args
abi_element_inputs
T acontract_abi
T aabi_element
args
kwargs
function_inputs
kwarg_names
sorted_arg_names
args_as_kwargs
duplicate_args
unknown_args
message
sorted_args
a__spec__
.eth_utils.address
^
is_text
a_HEX_ADDRESS_REGEXP
fullmatch

Checks if the given string of text type is an address in hexadecimal encoded form.
is_bytes

Checks if the given string is an address in raw bytes form.
is_hex_address
is_binary_address

Is the given string an address in any of the known formats?
hexstr_if_str
to_hex
lower
uValue must be any string, instead got type

is_address
aHexAddress
aHexStr
uUnknown format
u, attempted to normalize to

Converts an address to its normalized hexadecimal representation.
to_normalized_address
cast

Returns whether the provided value is an address in its normalized form.
aAddress
decode_hex

Convert a valid address to its canonical form (20-length bytes).
to_canonical_address

Returns `True` if the `value` is an address in its canonical form.
uBoth values must be valid addresses

Checks if both addresses are same or not.
encode_hex
keccak
remove_0x_prefix
T atext
add_0x_prefix
;l l*l aChecksumAddress

Makes a checksum address given a supported format.
address_hash
l anorm_address
upper
u<genexpr>
uto_checksum_address.<locals>.<genexpr>
to_checksum_address
islower
isupper
isnumeric
a_is_checksum_formatted
a__doc__
a__file__
origin
has_location
a__cached__
re
aAny
aUnion
eth_typing
T aAddress
aAnyAddress
aChecksumAddress
aHexAddress
aHexStr
aAnyAddress
conversions
T ahexstr_if_str
to_hex
crypto
T akeccak
hexadecimal
T aadd_0x_prefix
decode_hex
encode_hex
remove_0x_prefix
types
T ais_bytes
is_text
compile
u(0x)?[0-9a-f]{40}
aIGNORECASE
aASCII
value
return
is_normalized_address
address
is_canonical_address
left
right
is_same_address
is_checksum_address
is_checksum_formatted_address
ueth_utils\address.py
T a.0
wiaaddress_hash
norm_address
u<module eth_utils.address>
T avalue
unprefixed_value
T avalue
T aaddress
is_equal
T avalue
is_equal
T aleft
right
T aaddress
T avalue
norm_address
address_hash
checksum_address
T avalue
hex_address
a__spec__
.eth_utils.applicators
L
O
at_index
value
uNot enough values in iterable to apply formatter. Got:

u. Need:
formatter
apply_formatter_at_index
warnings
warn
aDeprecationWarning
T ucombine_argument_formatters(formatter1, formatter2)([item1, item2])has been deprecated and will be removed in a subsequent major version release of the eth-utils library. Update your calls to use apply_formatters_to_sequence([formatter1, formatter2], [item1, item2]) instead.
D astacklevel
l acurry
compose
a_formatter_at_index
u<genexpr>
ucombine_argument_formatters.<locals>.<genexpr>
formatters
sequence
uToo many formatters for sequence:
u formatters for
uToo few formatters for sequence:
apply_formatters_to_sequence
items
uCould not format invalid value
u as field
uCould not format invalid type
apply_formatters_to_dict
apply_formatter_to_array
uThe provided value did not satisfy any of the formatter conditions
keys
difference
key_mappings
intersection
uCould not apply key map due to conflicting key(s):
apply_key_map
uapply_key_map.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aCallable
aDict
aGenerator
aList
aTuple
decorators
T areturn_arg_type
return_arg_type
functional
T ato_dict
to_dict
toolz
T acompose
curry
aFormatters
T l areturn
combine_argument_formatters
T l acondition
T Q
Obool
apply_formatter_if
formatter_condition_pairs
apply_one_of_formatters
ueth_utils\applicators.py
T a.0
wkwvavalue
T a.0
index
formatter
a_formatter_at_index
u<module eth_utils.applicators>
T aformatter
at_index
value
index
item
T acondition
formatter
value
T aformatter
value
item
T aformatters
value
key
item
exc
new_error_message
T aformatters
sequence
formatter
item
T akey_mappings
value
key_conflicts
key
item
T aformatter_condition_pairs
value
condition
formatter
T aformatters
a_formatter_at_index
a__spec__
.eth_utils
P
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_eth_utils
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
version
a__version
abi
T aabi_to_signature
collapse_if_tuple
event_abi_to_log_topic
event_signature_to_log_topic
filter_abi_by_name
filter_abi_by_type
function_abi_to_4byte_selector
function_signature_to_4byte_selector
get_abi_input_names
get_abi_input_types
get_abi_output_names
get_abi_output_types
get_aligned_abi_inputs
get_all_event_abis
get_all_function_abis
get_normalized_abi_inputs
abi_to_signature
collapse_if_tuple
event_abi_to_log_topic
event_signature_to_log_topic
filter_abi_by_name
filter_abi_by_type
function_abi_to_4byte_selector
function_signature_to_4byte_selector
get_abi_input_names
get_abi_input_types
get_abi_output_names
get_abi_output_types
get_aligned_abi_inputs
get_all_event_abis
get_all_function_abis
get_normalized_abi_inputs
address
T ais_address
is_binary_address
is_canonical_address
is_checksum_address
is_checksum_formatted_address
is_hex_address
is_normalized_address
is_same_address
to_canonical_address
to_checksum_address
to_normalized_address
is_address
is_binary_address
is_canonical_address
is_checksum_address
is_checksum_formatted_address
is_hex_address
is_normalized_address
is_same_address
to_canonical_address
to_checksum_address
to_normalized_address
applicators
T aapply_formatter_at_index
apply_formatter_if
apply_formatter_to_array
apply_formatters_to_dict
apply_formatters_to_sequence
apply_key_map
apply_one_of_formatters
combine_argument_formatters
apply_formatter_at_index
apply_formatter_if
apply_formatter_to_array
apply_formatters_to_dict
apply_formatters_to_sequence
apply_key_map
apply_one_of_formatters
combine_argument_formatters
conversions
T ahexstr_if_str
text_if_str
to_bytes
to_hex
to_int
to_text
hexstr_if_str
text_if_str
to_bytes
to_hex
to_int
to_text
crypto
T akeccak
keccak
currency
T adenoms
from_wei
to_wei
denoms
from_wei
to_wei
decorators
T acombomethod
replace_exceptions
combomethod
replace_exceptions
encoding
T abig_endian_to_int
int_to_big_endian
big_endian_to_int
int_to_big_endian
exceptions
T aValidationError
aValidationError
functional
T	aapply_to_return_value
flatten_return
reversed_return
sort_return
to_dict
to_list
to_ordered_dict
to_set
to_tuple
apply_to_return_value
flatten_return
reversed_return
sort_return
to_dict
to_list
to_ordered_dict
to_set
to_tuple
hexadecimal
T aadd_0x_prefix
decode_hex
encode_hex
is_0x_prefixed
is_hex
is_hexstr
remove_0x_prefix
add_0x_prefix
decode_hex
encode_hex
is_0x_prefixed
is_hex
is_hexstr
remove_0x_prefix
humanize
T ahumanize_bytes
humanize_hash
humanize_hexstr
humanize_integer_sequence
humanize_ipfs_uri
humanize_seconds
humanize_wei
humanize_bytes
humanize_hash
humanize_hexstr
humanize_integer_sequence
humanize_ipfs_uri
humanize_seconds
humanize_wei
logging
T	aDEBUG2_LEVEL_NUM
aExtendedDebugLogger
aHasExtendedDebugLogger
aHasExtendedDebugLoggerMeta
aHasLogger
aHasLoggerMeta
get_extended_debug_logger
get_logger
setup_DEBUG2_logging
aDEBUG2_LEVEL_NUM
aExtendedDebugLogger
aHasExtendedDebugLogger
aHasExtendedDebugLoggerMeta
aHasLogger
aHasLoggerMeta
get_extended_debug_logger
get_logger
setup_DEBUG2_logging
module_loading
T aimport_string
import_string
network
T aNetwork
name_from_chain_id
network_from_chain_id
short_name_from_chain_id
aNetwork
name_from_chain_id
network_from_chain_id
short_name_from_chain_id
numeric
T aclamp
clamp
types
T ais_boolean
is_bytes
is_dict
is_integer
is_list
is_list_like
is_null
is_number
is_string
is_text
is_tuple
is_boolean
is_bytes
is_dict
is_integer
is_list
is_list_like
is_null
is_number
is_string
is_text
is_tuple
u5.2.0
a__version__
ueth_utils\__init__.py
u<module eth_utils>

a__spec__
.eth_utils.conversions
T
W
add_0x_prefix
aHexStr
lower
encode_hex
encode
T uutf-8
is_boolean
T u0x1
T u0x0
T Obytes
Obytearray
is_string
uUnsupported type: The primitive argument must be one of: bytes,bytearray, int or bool and not str
is_integer
cast
uUnsupported type: '

u'. Must be one of: bool, str, bytes, bytearray or int.

Auto converts any supported value into its hex representation.
Trims leading zeros, as defined in:
https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
l abig_endian_to_int
uPass in strings with keyword hexstr or text
T Oint
Obool
uInvalid type. Expected one of int/bool/str/bytes/bytearray. Got

Converts value to its integer representation.
Values are converted this way:
* primitive:
* bytes, bytearray, memoryview: big-endian integer
* bool: True => 1, False => 0
* int: unchanged
* hexstr: interpret hex as integer
* text: interpret as string of digits, like '12' => 12
d d
T Obytearray
Omemoryview
to_bytes
to_hex
T ahexstr
l u0x0
remove_0x_prefix
decode_hex
hexstr
uexpected a bool, int, byte or bytearray in first arg, or keyword of hexstr or text
decode
to_text
int_to_big_endian
uExpected an int, bytes, bytearray or hexstr.
T atext

Convert to a type, assuming that strings can be only unicode text (not a hexstr).
:param to_type function: takes the arguments (primitive, hexstr=hexstr, text=text),
eg~ to_bytes, to_text, to_hex, to_int, etc
:param text_or_primitive bytes, str, int: value to convert
is_hexstr
uwhen sending a str, it must be a hex string. Got:

Convert to a type, assuming that strings can be only hexstr (not unicode text).
:param to_type function: takes the arguments (primitive, hexstr=hexstr, text=text),
eg~ to_bytes, to_text, to_hex, to_int, etc
:param hexstr_or_primitive bytes, str, int: value to convert
a__doc__
a__file__
origin
has_location
a__cached__
aCallable
aOptional
aTypeVar
aUnion
eth_typing
T aHexStr
aPrimitives
aPrimitives
decorators
T avalidate_conversion_arguments
validate_conversion_arguments
encoding
T abig_endian_to_int
int_to_big_endian
hexadecimal
T aadd_0x_prefix
decode_hex
encode_hex
is_hexstr
remove_0x_prefix
types
T ais_boolean
is_integer
is_string
T wTwTaBytesLike
T nnnaprimitive
text
return
to_int
to_type
text_or_primitive
T Obytes
Oint
Ostr
text_if_str
hexstr_or_primitive
hexstr_if_str
ueth_utils\conversions.py
u<module eth_utils.conversions>
T ato_type
hexstr_or_primitive
T ato_type
text_or_primitive
T aprimitive
hexstr
text
T aprimitive
hexstr
text
byte_encoding
a__spec__
.eth_utils.crypto
*
keccak_256
to_bytes
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ueth_hash.auto
T akeccak
keccak
conversions
T ato_bytes
T nnnaprimitive
T Obytes
Oint
Obool
hexstr
text
return
ueth_utils\crypto.py
u<module eth_utils.crypto>
T aprimitive
hexstr
text

a__spec__
.eth_utils.currency
w
R
lower
units
uUnknown unit. Must be one of
w/akeys

aMIN_WEI
aMAX_WEI
uvalue must be between 0 and 2**256 - 1
localcontext
a__enter__
a__exit__
l  aprec
decimal
aDecimal
T avalue
context
T nnnaresult_value

Takes a number of wei and converts it to any other ether unit.
is_integer
is_string
T avalue
uUnsupported type. Must be one of integer, float, or string
T l
w.aindex
T w.l
multiplier
uResulting wei value must be between 0 and 2**256 - 1

Takes a number of a unit and converts it to wei.
a__doc__
a__file__
origin
has_location
a__cached__
T alocalcontext
aUnion
types
T ais_integer
is_string
T aunits
