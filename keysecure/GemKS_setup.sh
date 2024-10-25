#!/bin/sh

# to run; source GemKS_setup.sh
#         or . GemKS_setup.sh

export SFNT_HSMAPI_BASE=/opt/gemengine/keysecure
export NAE_Properties_Conf_Filename=$SFNT_HSMAPI_BASE/GemKS.properties
export IngrianNAE_Properties_Conf_Slot_ID_Max=100
export IngrianNAE_Properties_Conf_SessionID_Max=100
