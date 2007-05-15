/******************************************************************************
** $Id$
**
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
** 
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
** 
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
** 
** Project: OpcUa Wireshark Plugin
**
** Description: This file contains protocol field handles.
**
** This file was autogenerated on 8.5.2007 18:53:26.
** DON'T MODIFY THIS FILE!
**
******************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>

extern int hf_opcua_TestId;
extern int hf_opcua_Iteration;
extern int hf_opcua_ServerUris;
extern int hf_opcua_ProfileUris;
extern int hf_opcua_ClientCertificate;
extern int hf_opcua_SecureChannelId;
extern int hf_opcua_SecurityPolicyUri;
extern int hf_opcua_ClientNonce;
extern int hf_opcua_RequestedLifetime;
extern int hf_opcua_ServerCertificate;
extern int hf_opcua_ServerNonce;
extern int hf_opcua_ClientName;
extern int hf_opcua_RequestedSessionTimeout;
extern int hf_opcua_SessionId;
extern int hf_opcua_RevisedSessionTimeout;
extern int hf_opcua_LocaleIds;
extern int hf_opcua_CertificateResults;
extern int hf_opcua_SequenceNumber;
extern int hf_opcua_Results;
extern int hf_opcua_MaxResultsToReturn;
extern int hf_opcua_IncludeSubtypes;
extern int hf_opcua_NodeClassMask;
extern int hf_opcua_ContinuationPoint;
extern int hf_opcua_ReleaseContinuationPoint;
extern int hf_opcua_RevisedContinuationPoint;
extern int hf_opcua_MaxDescriptionsToReturn;
extern int hf_opcua_MaxReferencesToReturn;
extern int hf_opcua_MaxReferencedNodesToReturn;
extern int hf_opcua_MaxTime;
extern int hf_opcua_MaxAge;
extern int hf_opcua_ReleaseContinuationPoints;
extern int hf_opcua_SubscriptionId;
extern int hf_opcua_MonitoredItemIds;
extern int hf_opcua_TriggeringItemId;
extern int hf_opcua_LinksToAdd;
extern int hf_opcua_LinksToRemove;
extern int hf_opcua_AddResults;
extern int hf_opcua_RemoveResults;
extern int hf_opcua_RequestedPublishingInterval;
extern int hf_opcua_RequestedLifetimeCounter;
extern int hf_opcua_RequestedMaxKeepAliveCount;
extern int hf_opcua_PublishingEnabled;
extern int hf_opcua_Priority;
extern int hf_opcua_RevisedPublishingInterval;
extern int hf_opcua_RevisedLifetimeCounter;
extern int hf_opcua_RevisedMaxKeepAliveCount;
extern int hf_opcua_SubscriptionIds;
extern int hf_opcua_AvailableSequenceNumbers;
extern int hf_opcua_MoreNotifications;
extern int hf_opcua_RetransmitSequenceNumber;
extern int hf_opcua_IsInverse;
extern int hf_opcua_ServerIndex;
extern int hf_opcua_NodeClass;
extern int hf_opcua_EventNotifier;
extern int hf_opcua_IsAbstract;
extern int hf_opcua_ArraySize;
extern int hf_opcua_AccessLevel;
extern int hf_opcua_UserAccessLevel;
extern int hf_opcua_MinimumSamplingInterval;
extern int hf_opcua_Historizing;
extern int hf_opcua_Symmetric;
extern int hf_opcua_Executable;
extern int hf_opcua_UserExecutable;
extern int hf_opcua_ContainsNoLoops;
extern int hf_opcua_Index;
extern int hf_opcua_Uri;
extern int hf_opcua_Name;
extern int hf_opcua_StatusCode;
extern int hf_opcua_EventId;
extern int hf_opcua_SourceName;
extern int hf_opcua_Time;
extern int hf_opcua_ReceiveTime;
extern int hf_opcua_Severity;
extern int hf_opcua_Digest;
extern int hf_opcua_SymmetricSignature;
extern int hf_opcua_SymmetricKeyWrap;
extern int hf_opcua_SymmetricEncryption;
extern int hf_opcua_SymmetricKeyLength;
extern int hf_opcua_AsymmetricSignature;
extern int hf_opcua_AsymmetricKeyWrap;
extern int hf_opcua_AsymmetricEncryption;
extern int hf_opcua_MinimumAsymmetricKeyLength;
extern int hf_opcua_MaximumAsymmetricKeyLength;
extern int hf_opcua_DerivedKey;
extern int hf_opcua_DerivedEncryptionKeyLength;
extern int hf_opcua_DerivedSignatureKeyLength;
extern int hf_opcua_IssuerType;
extern int hf_opcua_IssuerUrl;
extern int hf_opcua_ServerUri;
extern int hf_opcua_DiscoveryUrls;
extern int hf_opcua_EndpointUrl;
extern int hf_opcua_SupportedProfiles;
extern int hf_opcua_SendTimeout;
extern int hf_opcua_OperationTimeout;
extern int hf_opcua_UseBinaryEncoding;
extern int hf_opcua_MaxMessageSize;
extern int hf_opcua_MaxArrayLength;
extern int hf_opcua_MaxStringLength;
extern int hf_opcua_UserName;
extern int hf_opcua_Password;
extern int hf_opcua_HashAlgorithm;
extern int hf_opcua_CertificateData;
extern int hf_opcua_TokenData;
extern int hf_opcua_ProfileUri;
extern int hf_opcua_ProfileName;
extern int hf_opcua_ApplicationUri;
extern int hf_opcua_ManufacturerName;
extern int hf_opcua_ApplicationName;
extern int hf_opcua_SoftwareVersion;
extern int hf_opcua_BuildNumber;
extern int hf_opcua_BuildDate;
extern int hf_opcua_IssuedBy;
extern int hf_opcua_IssuedDate;
extern int hf_opcua_ExpirationDate;
extern int hf_opcua_ApplicationCertificate;
extern int hf_opcua_IssuerCertificateThumbprint;
extern int hf_opcua_IssuerSignatureAlgorithm;
extern int hf_opcua_IssuerSignature;
extern int hf_opcua_IsForward;
extern int hf_opcua_TargetServerUri;
extern int hf_opcua_TargetNodeClass;
extern int hf_opcua_DeleteTargetReferences;
extern int hf_opcua_ServerId;
extern int hf_opcua_ServiceLevel;
extern int hf_opcua_SamplingRate;
extern int hf_opcua_SamplingErrorCount;
extern int hf_opcua_SampledMonitoredItemsCount;
extern int hf_opcua_MaxSampledMonitoredItemsCount;
extern int hf_opcua_DisabledMonitoredItemsSamplingCount;
extern int hf_opcua_ServerViewCount;
extern int hf_opcua_CurrentSessionCount;
extern int hf_opcua_CumulatedSessionCount;
extern int hf_opcua_SecurityRejectedSessionCount;
extern int hf_opcua_RejectSessionCount;
extern int hf_opcua_SessionTimeoutCount;
extern int hf_opcua_SessionAbortCount;
extern int hf_opcua_SamplingRateCount;
extern int hf_opcua_PublishingRateCount;
extern int hf_opcua_CurrentSubscriptionCount;
extern int hf_opcua_CumulatedSubscriptionCount;
extern int hf_opcua_SecurityRejectedRequestsCount;
extern int hf_opcua_RejectedRequestsCount;
extern int hf_opcua_StartTime;
extern int hf_opcua_CurrentTime;
extern int hf_opcua_TotalCount;
extern int hf_opcua_UnauthorizedCount;
extern int hf_opcua_ErrorCount;
extern int hf_opcua_ActualSessionTimeout;
extern int hf_opcua_ClientConnectionTime;
extern int hf_opcua_ClientLastContactTime;
extern int hf_opcua_CurrentSubscriptionsCount;
extern int hf_opcua_CurrentMonitoredItemsCount;
extern int hf_opcua_CurrentPublishRequestsInQueue;
extern int hf_opcua_CurrentPublishTimerExpirations;
extern int hf_opcua_KeepAliveCount;
extern int hf_opcua_CurrentRepublishRequestsInQueue;
extern int hf_opcua_MaxRepublishRequestsInQueue;
extern int hf_opcua_RepublishCounter;
extern int hf_opcua_PublishingCount;
extern int hf_opcua_PublishingQueueOverflowCount;
extern int hf_opcua_ClientUserIdOfSession;
extern int hf_opcua_ClientUserIdHistory;
extern int hf_opcua_AuthenticationMechanism;
extern int hf_opcua_Encoding;
extern int hf_opcua_TransportProtocol;
extern int hf_opcua_SecurityPolicy;
extern int hf_opcua_PublishingInterval;
extern int hf_opcua_MaxKeepAliveCount;
extern int hf_opcua_ModifyCount;
extern int hf_opcua_EnableCount;
extern int hf_opcua_DisableCount;
extern int hf_opcua_RepublishRequestCount;
extern int hf_opcua_RepublishMessageRequestCount;
extern int hf_opcua_RepublishMessageCount;
extern int hf_opcua_TransferRequestCount;
extern int hf_opcua_TransferredToAltClientCount;
extern int hf_opcua_TransferredToSameClientCount;
extern int hf_opcua_PublishRequestCount;
extern int hf_opcua_DataChangeNotificationsCount;
extern int hf_opcua_EventNotificationsCount;
extern int hf_opcua_NotificationsCount;
extern int hf_opcua_LateStateCount;
extern int hf_opcua_KeepAliveStateCount;
extern int hf_opcua_Low;
extern int hf_opcua_High;
extern int hf_opcua_NamespaceUri;
extern int hf_opcua_UnitId;
extern int hf_opcua_Message;
extern int hf_opcua_AnnotationTime;
extern int hf_opcua_Id;
extern int hf_opcua_Description;
extern int hf_opcua_Timestamp;
extern int hf_opcua_Boolean;
extern int hf_opcua_SByte;
extern int hf_opcua_Byte;
extern int hf_opcua_Int16;
extern int hf_opcua_UInt16;
extern int hf_opcua_Int32;
extern int hf_opcua_UInt32;
extern int hf_opcua_Int64;
extern int hf_opcua_UInt64;
extern int hf_opcua_Float;
extern int hf_opcua_Double;
extern int hf_opcua_String;
extern int hf_opcua_DateTime;
extern int hf_opcua_Guid;
extern int hf_opcua_ByteString;
extern int hf_opcua_XmlElement;
extern int hf_opcua_RequestId;
extern int hf_opcua_ReturnDiagnostics;
extern int hf_opcua_AuditLogEntryId;
extern int hf_opcua_TimeoutHint;
extern int hf_opcua_ServiceResult;
extern int hf_opcua_StringTable;
extern int hf_opcua_Value1;
extern int hf_opcua_Value2;
extern int hf_opcua_Booleans;
extern int hf_opcua_SBytes;
extern int hf_opcua_Int16s;
extern int hf_opcua_UInt16s;
extern int hf_opcua_Int32s;
extern int hf_opcua_UInt32s;
extern int hf_opcua_Int64s;
extern int hf_opcua_UInt64s;
extern int hf_opcua_Floats;
extern int hf_opcua_Doubles;
extern int hf_opcua_Strings;
extern int hf_opcua_DateTimes;
extern int hf_opcua_Guids;
extern int hf_opcua_ByteStrings;
extern int hf_opcua_XmlElements;
extern int hf_opcua_StatusCodes;
extern int hf_opcua_SemaphoreFilePath;
extern int hf_opcua_IsOnline;
extern int hf_opcua_ChannelId;
extern int hf_opcua_TokenId;
extern int hf_opcua_CreatedAt;
extern int hf_opcua_RevisedLifetime;
extern int hf_opcua_Algorithm;
extern int hf_opcua_Signature;
extern int hf_opcua_PropertyStatusCode;
extern int hf_opcua_ViewVersion;
extern int hf_opcua_RelativePath;
extern int hf_opcua_AttributeId;
extern int hf_opcua_IndexRange;
extern int hf_opcua_IncludeSubTypes;
extern int hf_opcua_Alias;
extern int hf_opcua_Result;
extern int hf_opcua_IndexOfInvalidElement;
extern int hf_opcua_AttributeStatusCodes;
extern int hf_opcua_NumValuesPerNode;
extern int hf_opcua_EndTime;
extern int hf_opcua_IsReadModified;
extern int hf_opcua_ReturnBounds;
extern int hf_opcua_ResampleInterval;
extern int hf_opcua_ReqTimes;
extern int hf_opcua_ClientHandle;
extern int hf_opcua_PerformInsert;
extern int hf_opcua_PerformReplace;
extern int hf_opcua_IsDeleteModified;
extern int hf_opcua_OperationResult;
extern int hf_opcua_InputArgumentResults;
extern int hf_opcua_DeadbandType;
extern int hf_opcua_DeadbandValue;
extern int hf_opcua_SelectClauseResults;
extern int hf_opcua_SamplingInterval;
extern int hf_opcua_QueueSize;
extern int hf_opcua_DiscardOldest;
extern int hf_opcua_MonitoredItemId;
extern int hf_opcua_RevisedSamplingInterval;
extern int hf_opcua_RevisedQueueSize;
extern int hf_opcua_MonitorItemId;
extern int hf_opcua_PublishTime;
extern int hf_opcua_AvailableSequenceNumbersRanges;

/** Register field types. */
void registerFieldTypes(int proto);
