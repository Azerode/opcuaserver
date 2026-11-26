// Interoperability check of fastua against the OPC Foundation reference
// client stack (UA-.NETStandard).
//
// usage: serve.sh <fastua> dotnet fastua-interop-dotnet.dll   (FASTUA_URL, FASTUA_HTTPS_URL, FASTUA_WORK)
//
// Discovery, every RSA security policy and mode, user tokens, the HTTPS
// transport (https-uabinary), the whole address space read through the
// stack's node model, Write of every built-in type, TranslateBrowsePaths,
// RegisterNodes, subscriptions (data changes, events, alarm acknowledge,
// TransferSubscriptions to a new session), Call, HistoryRead (raw,
// processed, at time, events) and HistoryUpdate. Exits non-zero on failure.
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;

static class Interop
{
    static readonly string Url = Environment.GetEnvironmentVariable("FASTUA_URL");
    static readonly string HttpsUrl = Environment.GetEnvironmentVariable("FASTUA_HTTPS_URL");
    static readonly string Work = Environment.GetEnvironmentVariable("FASTUA_WORK");
    static readonly List<string> Failures = new();
    static ApplicationConfiguration Config;
    static ushort Ns;

    static void Check(string label, bool ok, string detail = null)
    {
        Console.WriteLine((ok ? "PASS " : "FAIL ") + label + (detail != null ? $"  ({detail})" : ""));
        if (!ok) Failures.Add(label);
    }

    static async Task<int> Main()
    {
        try
        {
            await Setup();
            await Discovery();
            await Policies();
            await Users();
            await Https();
            using var s = await Connect(Url, SecurityPolicies.Basic256Sha256, MessageSecurityMode.SignAndEncrypt,
                User("operator", "s3cret"));
            Ns = (ushort)s.NamespaceUris.GetIndex("urn:fastua:interop:plant");
            Check("namespace array", Ns > 0, string.Join(",", s.NamespaceUris.ToArray()));
            await AddressSpace(s);
            await Plant(s);
            await Subscriptions(s);
            await History(s);
            await s.CloseAsync();
        }
        catch (Exception e)
        {
            Check("exception", false, e.ToString());
        }
        if (Failures.Count > 0)
        {
            Console.WriteLine($"{Failures.Count} failure(s): {string.Join(", ", Failures)}");
            return 1;
        }
        Console.WriteLine("all .NET interop checks passed");
        return 0;
    }

    static async Task Setup()
    {
        string pki = $"{Work}/dotnet-pki";
        Config = new ApplicationConfiguration
        {
            ApplicationName = "fastua-interop-dotnet",
            ApplicationUri = "urn:fastua:interop:dotnet",
            ApplicationType = ApplicationType.Client,
            SecurityConfiguration = new SecurityConfiguration
            {
                ApplicationCertificate = new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = $"{pki}/own",
                    SubjectName = "CN=fastua-interop-dotnet, O=fastua",
                },
                TrustedPeerCertificates = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = $"{pki}/trusted" },
                TrustedIssuerCertificates = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = $"{pki}/issuers" },
                RejectedCertificateStore = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = $"{pki}/rejected" },
                AutoAcceptUntrustedCertificates = true,
                AddAppCertToTrustedStore = false,
                RejectSHA1SignedCertificates = true,
                MinimumCertificateKeySize = 2048,
            },
            TransportConfigurations = new TransportConfigurationCollection(),
            TransportQuotas = new TransportQuotas { OperationTimeout = 15000, MaxMessageSize = 4 * 1024 * 1024 },
            ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = 60000 },
            TraceConfiguration = new TraceConfiguration(),
        };
        await Config.Validate(ApplicationType.Client);
        // The test server has a self-signed certificate made for its host name.
        Config.CertificateValidator.CertificateValidation += (_, e) => e.Accept = true;
        var app = new ApplicationInstance { ApplicationName = Config.ApplicationName, ApplicationType = ApplicationType.Client, ApplicationConfiguration = Config };
        bool ok = await app.CheckApplicationInstanceCertificates(false, 2048);
        Check("client certificate", ok);
    }

    static async Task<EndpointDescriptionCollection> Endpoints(string url)
    {
        using var d = DiscoveryClient.Create(new Uri(url), EndpointConfiguration.Create(Config));
        return await d.GetEndpointsAsync(null);
    }

    static async Task<Session> Connect(string url, string policy, MessageSecurityMode mode, IUserIdentity user = null)
    {
        var eps = await Endpoints(url);
        var ed = eps.FirstOrDefault(e => e.SecurityPolicyUri == policy && e.SecurityMode == mode
            && e.EndpointUrl.StartsWith(url.Split(':')[0] + ":"))
            ?? throw new Exception($"no endpoint {policy} {mode} at {url}");
        var endpoint = new ConfiguredEndpoint(null, ed, EndpointConfiguration.Create(Config));
        return await Session.Create(Config, endpoint, false, "fastua-interop", 60000,
            user ?? new UserIdentity(new AnonymousIdentityToken()), null);
    }

    static async Task Discovery()
    {
        var eps = await Endpoints(Url);
        var policies = eps.Select(e => e.SecurityPolicyUri).ToHashSet();
        foreach (var p in new[] { SecurityPolicies.None, SecurityPolicies.Basic256Sha256, SecurityPolicies.Aes128_Sha256_RsaOaep, SecurityPolicies.Aes256_Sha256_RsaPss })
            Check($"GetEndpoints offers {SecurityPolicies.GetDisplayName(p)}", policies.Contains(p));
        Check("server certificate on secure endpoints", eps.Where(e => e.SecurityMode != MessageSecurityMode.None)
            .All(e => e.ServerCertificate != null && e.ServerCertificate.Length > 0));
        Check("user token policies", eps.All(e => e.UserIdentityTokens.Count > 0
            && e.UserIdentityTokens.Select(t => t.PolicyId).Distinct().Count() == e.UserIdentityTokens.Count));
        using var d = DiscoveryClient.Create(new Uri(Url), EndpointConfiguration.Create(Config));
        var servers = await d.FindServersAsync(null);
        Check("FindServers", servers.Count == 1 && servers[0].ApplicationUri == "urn:fastua:interop:server"
            && servers[0].ApplicationType == ApplicationType.Server, servers.FirstOrDefault()?.ApplicationUri);
    }

    static async Task Policies()
    {
        var list = new List<(string, MessageSecurityMode)> { (SecurityPolicies.None, MessageSecurityMode.None) };
        foreach (var p in new[] { SecurityPolicies.Basic256Sha256, SecurityPolicies.Aes128_Sha256_RsaOaep, SecurityPolicies.Aes256_Sha256_RsaPss })
            foreach (var m in new[] { MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt })
                list.Add((p, m));
        foreach (var (p, m) in list)
        {
            string label = $"{SecurityPolicies.GetDisplayName(p)} {m}";
            try
            {
                using var s = await Connect(Url, p, m);
                // A response of several chunks.
                var nodes = new ReadValueIdCollection(Enumerable.Range(0, 800).Select(_ =>
                    new ReadValueId { NodeId = VariableIds.Server_ServerStatus, AttributeId = Attributes.Value }));
                var r = await s.ReadAsync(null, 0, TimestampsToReturn.Both, nodes, default);
                var status = r.Results[0].Value as ExtensionObject;
                Check(label, r.Results.Count == 800 && r.Results.All(v => StatusCode.IsGood(v.StatusCode))
                    && (status?.Body as ServerStatusDataType)?.State == ServerState.Running);
                await s.CloseAsync();
            }
            catch (Exception e)
            {
                Check(label, false, e.Message);
            }
        }
    }

    static async Task Users()
    {
        try
        {
            using var s = await Connect(Url, SecurityPolicies.Basic256Sha256, MessageSecurityMode.SignAndEncrypt, User("operator", "nope"));
            Check("wrong password rejected", false, "connected");
        }
        catch (ServiceResultException e)
        {
            Check("wrong password rejected", e.StatusCode == StatusCodes.BadUserAccessDenied || e.StatusCode == StatusCodes.BadIdentityTokenRejected, e.Message);
        }
        using var v = await Connect(Url, SecurityPolicies.Aes128_Sha256_RsaOaep, MessageSecurityMode.Sign, User("viewer", "s3cret"));
        var w = await v.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = new NodeId(1u, 2), AttributeId = Attributes.Value,
            Value = new DataValue(new Variant(5)) } }, default);
        Check("viewer write refused", w.Results[0] == StatusCodes.BadUserAccessDenied, w.Results[0].ToString());
        await v.CloseAsync();
        // Password over SecurityPolicy None: encrypted with the token policy.
        using var n = await Connect(Url, SecurityPolicies.None, MessageSecurityMode.None, User("operator", "s3cret"));
        Check("user name over SecurityPolicy None", n.Connected);
        await n.CloseAsync();
    }

    static async Task Https()
    {
        var eps = await Endpoints(HttpsUrl);
        Check("HTTPS GetEndpoints", eps.Any(e => e.TransportProfileUri == Profiles.HttpsBinaryTransport && e.EndpointUrl.TrimEnd('/') == HttpsUrl),
            string.Join(",", eps.Where(e => e.EndpointUrl.StartsWith("opc.https")).Select(e => $"{e.EndpointUrl} {e.TransportProfileUri}")));
        using var s = await Connect(HttpsUrl, SecurityPolicies.None, MessageSecurityMode.None, User("operator", "s3cret"));
        var r = await s.ReadAsync(null, 0, TimestampsToReturn.Both, new ReadValueIdCollection {
            new ReadValueId { NodeId = VariableIds.Server_ServerStatus_State, AttributeId = Attributes.Value } }, default);
        Check("HTTPS session and Read", StatusCode.IsGood(r.Results[0].StatusCode) && (int)r.Results[0].Value == 0);
        var ns = (ushort)s.NamespaceUris.GetIndex("urn:fastua:interop:plant");
        var b = await s.BrowseAsync(null, null, 0, new BrowseDescriptionCollection { new BrowseDescription {
            NodeId = ObjectIds.ObjectsFolder, BrowseDirection = BrowseDirection.Forward, ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences,
            IncludeSubtypes = true, ResultMask = (uint)BrowseResultMask.All } }, default);
        Check("HTTPS Browse", b.Results[0].References.Any(x => x.BrowseName.Name == "Plant"));
        // Subscriptions work over HTTPS: Publish is a long-polling POST.
        var sub = new Subscription(s.DefaultSubscription) { PublishingInterval = 50 };
        var item = new MonitoredItem(sub.DefaultItem) { StartNodeId = new NodeId("Recipe", ns), SamplingInterval = 20 };
        var seen = new List<object>();
        item.Notification += (_, e) => { lock (seen) seen.Add(((MonitoredItemNotification)e.NotificationValue).Value.Value); };
        sub.AddItem(item);
        s.AddSubscription(sub);
        await sub.CreateAsync();
        await Task.Delay(300);
        await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = new NodeId("Recipe", ns), AttributeId = Attributes.Value,
            Value = new DataValue(new Variant("over https")) } }, default);
        await Task.Delay(500);
        lock (seen) Check("HTTPS subscription", seen.Contains("over https"), string.Join(",", seen));
        await sub.DeleteAsync(true);
        await s.CloseAsync();
    }

    static async Task AddressSpace(Session s)
    {
        // Every node under the root, read through the stack's node model
        // (every attribute of the node class, decoded and type checked).
        var seen = new HashSet<NodeId> { ObjectIds.RootFolder };
        var frontier = new List<NodeId> { ObjectIds.RootFolder };
        int pages = 0;
        // As many nodes per Browse as the server keeps continuation points.
        var maxCp = Convert.ToInt32((await s.ReadValueAsync(VariableIds.Server_ServerCapabilities_MaxBrowseContinuationPoints)).Value);
        Check("MaxBrowseContinuationPoints", maxCp > 0, maxCp.ToString());
        while (frontier.Count > 0)
        {
            var next = new List<NodeId>();
            foreach (var batch in frontier.Chunk(Math.Min(100, maxCp)))
            {
                var desc = new BrowseDescriptionCollection(batch.Select(n => new BrowseDescription { NodeId = n,
                    BrowseDirection = BrowseDirection.Forward, ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences,
                    IncludeSubtypes = true, ResultMask = (uint)BrowseResultMask.All }));
                var res = (await s.BrowseAsync(null, null, 5, desc, default)).Results;
                while (true)
                {
                    var cps = new ByteStringCollection();
                    foreach (var r in res)
                    {
                        if (StatusCode.IsBad(r.StatusCode)) throw new Exception($"browse {r.StatusCode}");
                        foreach (var rd in r.References)
                        {
                            var id = ExpandedNodeId.ToNodeId(rd.NodeId, s.NamespaceUris);
                            if (seen.Add(id)) next.Add(id);
                        }
                        if (r.ContinuationPoint != null && r.ContinuationPoint.Length > 0) cps.Add(r.ContinuationPoint);
                    }
                    if (cps.Count == 0) break;
                    pages++;
                    res = (await s.BrowseNextAsync(null, false, cps, default)).Results;
                }
            }
            frontier = next;
        }
        Check("browse the whole address space", seen.Count > 4000 && pages > 0, $"{seen.Count} nodes, {pages} BrowseNext");
        var (nodes, errors) = await s.ReadNodesAsync(seen.ToList(), NodeClass.Unspecified, true);
        var bad = errors.Select((e, i) => (e, i)).Where(x => ServiceResult.IsBad(x.e)).Select(x => $"{seen.ElementAt(x.i)}: {x.e}").ToList();
        Check("read every node (node model)", bad.Count == 0 && nodes.Count == seen.Count, bad.Count > 0 ? string.Join("; ", bad.Take(5)) : $"{nodes.Count} nodes");

        // DataTypeDefinition decodes as StructureDefinition / EnumDefinition.
        var types = nodes.OfType<DataTypeNode>().ToList();
        var defs = await s.ReadAsync(null, 0, TimestampsToReturn.Neither, new ReadValueIdCollection(types.Select(t =>
            new ReadValueId { NodeId = t.NodeId, AttributeId = Attributes.DataTypeDefinition })), default);
        int structs = 0, enums = 0;
        var wrong = new List<string>();
        for (int i = 0; i < types.Count; i++)
        {
            var dv = defs.Results[i];
            if (dv.StatusCode == StatusCodes.BadAttributeIdInvalid) continue;
            var body = (dv.Value as ExtensionObject)?.Body;
            if (body is StructureDefinition sd && sd.Fields.Count > 0 || body is StructureDefinition { StructureType: StructureType.Structure }) structs++;
            else if (body is EnumDefinition ed && ed.Fields.Count > 0) enums++;
            else wrong.Add($"{types[i].BrowseName}: {dv.StatusCode} {body?.GetType().Name}");
        }
        Check("DataTypeDefinition decodes", structs > 150 && enums > 50 && wrong.Count == 0,
            $"{structs} structures, {enums} enumerations{(wrong.Count > 0 ? ", " + string.Join("; ", wrong.Take(5)) : "")}");

        // Type hierarchy as the stack's type tree sees it.
        await s.FetchTypeTreeAsync(new ExpandedNodeId(ObjectTypeIds.BaseEventType));
        Check("type tree (ExclusiveLimitAlarmType is a ConditionType)",
            s.TypeTree.IsTypeOf(ObjectTypeIds.ExclusiveLimitAlarmType, ObjectTypeIds.ConditionType));
        var serverNode = await s.ReadNodeAsync(ObjectIds.Server);
        Check("Server object is an event notifier", serverNode is ObjectNode o && (o.EventNotifier & EventNotifiers.SubscribeToEvents) != 0);
    }

    static UserIdentity User(string name, string password) => new(name, System.Text.Encoding.UTF8.GetBytes(password));

    static NodeId Id(object x) => x is uint u ? new NodeId(u, Ns) : new NodeId((string)x, Ns);

    static async Task Plant(Session s)
    {
        var paths = new BrowsePathCollection
        {
            new BrowsePath { StartingNode = ObjectIds.ObjectsFolder, RelativePath = RelativePath.Parse($"/{Ns}:Plant/{Ns}:Tank/{Ns}:Level", s.TypeTree) },
            new BrowsePath { StartingNode = ObjectIds.Server, RelativePath = RelativePath.Parse("/ServerStatus/BuildInfo/ProductName", s.TypeTree) },
            new BrowsePath { StartingNode = ObjectIds.ObjectsFolder, RelativePath = RelativePath.Parse($"/{Ns}:Nope", s.TypeTree) },
        };
        var t = await s.TranslateBrowsePathsToNodeIdsAsync(null, paths, default);
        Check("TranslateBrowsePaths", t.Results[0].Targets.Count == 1 && (NodeId)t.Results[0].Targets[0].TargetId == Id("Level")
            && (NodeId)t.Results[1].Targets[0].TargetId == VariableIds.Server_ServerStatus_BuildInfo_ProductName
            && t.Results[2].StatusCode == StatusCodes.BadNoMatch, string.Join(",", t.Results.Select(r => r.StatusCode)));

        var level = (VariableNode)await s.ReadNodeAsync(Id("Level"));
        Check("Level attributes", level.DataType == DataTypeIds.Double && level.ValueRank == ValueRanks.Scalar && level.Historizing
            && (level.AccessLevel & AccessLevels.HistoryRead) != 0 && (level.UserAccessLevel & AccessLevels.CurrentWrite) != 0,
            $"{level.DataType} {level.ValueRank} {level.AccessLevel}");
        var euRange = await s.ReadValueAsync(Id("Level"));
        var range = await s.TranslateBrowsePathsToNodeIdsAsync(null, new BrowsePathCollection { new BrowsePath { StartingNode = Id("Level"),
            RelativePath = RelativePath.Parse("/EURange", s.TypeTree) } }, default);
        var eu = await s.ReadValueAsync((NodeId)range.Results[0].Targets[0].TargetId);
        Check("EURange property (AnalogItemType)", (eu.Value as ExtensionObject)?.Body is Opc.Ua.Range r && r.High == 200, eu.ToString());

        var guid = new Uuid(Guid.Parse("72962b91-fa75-4ae6-8d28-b404dc7daf63"));
        var stamp = new DateTime(2026, 11, 25, 12, 0, 0, DateTimeKind.Utc);
        var cases = new (object id, Variant v)[]
        {
            (1u, new Variant(-42)), (2u, new Variant(true)), (3u, new Variant(ulong.MaxValue - 1)), ("Recipe", new Variant("Crème brûlée")),
            ("Ratio", new Variant(1.25f)), ("Stamp", new Variant(stamp)), ("Id", new Variant(guid)), ("Blob", new Variant(new byte[] { 9, 8, 7 })),
            ("Level", new Variant(12.5)),
        };
        var w = await s.WriteAsync(null, new WriteValueCollection(cases.Select(c => new WriteValue { NodeId = Id(c.id),
            AttributeId = Attributes.Value, Value = new DataValue(c.v) })), default);
        Check("write every type", w.Results.All(StatusCode.IsGood), string.Join(",", w.Results));
        var back = await s.ReadAsync(null, 0, TimestampsToReturn.Both, new ReadValueIdCollection(cases.Select(c =>
            new ReadValueId { NodeId = Id(c.id), AttributeId = Attributes.Value })), default);
        var diff = cases.Select((c, i) => (c, dv: back.Results[i])).Where(x => !Utils.IsEqual(x.c.v.Value, x.dv.Value)
            || x.dv.SourceTimestamp == DateTime.MinValue).Select(x => $"{x.c.id}={x.dv.Value}").ToList();
        Check("read back every type with timestamps", diff.Count == 0, string.Join("; ", diff));
        var wrongType = await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = Id(1u), AttributeId = Attributes.Value,
            Value = new DataValue(new Variant(1.5)) } }, default);
        Check("write with wrong type", wrongType.Results[0] == StatusCodes.BadTypeMismatch, wrongType.Results[0].ToString());
        var attrWrite = await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = Id(1u), AttributeId = Attributes.DisplayName,
            Value = new DataValue(new Variant(new LocalizedText("x"))) } }, default);
        Check("write of a non-writable attribute", attrWrite.Results[0] == StatusCodes.BadNotWritable, attrWrite.Results[0].ToString());

        var reg = await s.RegisterNodesAsync(null, new NodeIdCollection { Id(1u), Id("Recipe") }, default);
        var rr = await s.ReadValueAsync(reg.RegisteredNodeIds[0]);
        Check("RegisterNodes", reg.RegisteredNodeIds.Count == 2 && (int)rr.Value == -42);
        await s.UnregisterNodesAsync(null, reg.RegisteredNodeIds, default);
    }

    static async Task Subscriptions(Session s)
    {
        var sub = new Subscription(s.DefaultSubscription) { PublishingInterval = 20, KeepAliveCount = 10, LifetimeCount = 300 };
        var values = new List<int>();
        var item = new MonitoredItem(sub.DefaultItem) { StartNodeId = Id(1u), SamplingInterval = 10, QueueSize = 10 };
        item.Notification += (_, e) => { lock (values) values.Add((int)((MonitoredItemNotification)e.NotificationValue).Value.Value); };
        sub.AddItem(item);

        // Events of the Server object, and limit alarms only (where clause).
        var events = new List<EventFieldList>();
        var evFilter = new EventFilter();
        evFilter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.EventType);
        evFilter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.SourceName);
        evFilter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.EventId);
        evFilter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.Severity);
        evFilter.AddSelectClause(ObjectTypeIds.ConditionType, "", Attributes.NodeId);
        evFilter.AddSelectClause(ObjectTypeIds.AlarmConditionType, "ActiveState/Id");
        evFilter.AddSelectClause(ObjectTypeIds.AlarmConditionType, "AckedState/Id");
        evFilter.WhereClause.Push(FilterOperator.OfType, new LiteralOperand(new Variant(ObjectTypeIds.ExclusiveLimitAlarmType)));
        var ev = new MonitoredItem(sub.DefaultItem) { StartNodeId = ObjectIds.Server, AttributeId = Attributes.EventNotifier,
            SamplingInterval = 0, QueueSize = 100, Filter = evFilter };
        ev.Notification += (_, e) => { lock (events) events.Add((EventFieldList)e.NotificationValue); };
        sub.AddItem(ev);
        s.AddSubscription(sub);
        await sub.CreateAsync();
        Check("monitored items created", item.Status.Created && ev.Status.Created && ServiceResult.IsGood(ev.Status.Error),
            ev.Status.Error?.ToString());
        await Task.Delay(300);
        foreach (var v in new[] { 7, 8, 9 })
        {
            await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = Id(1u), AttributeId = Attributes.Value, Value = new DataValue(new Variant(v)) } }, default);
            await Task.Delay(50);
        }
        await Task.Delay(300);
        lock (values) Check("data change notifications", values.FirstOrDefault() == -42 && values.TakeLast(3).SequenceEqual(new[] { 7, 8, 9 }), string.Join(",", values));

        await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = Id("Level"), AttributeId = Attributes.Value, Value = new DataValue(new Variant(160.0)) } }, default);
        await Task.Delay(400);
        EventFieldList active;
        lock (events) active = events.LastOrDefault(e => e.EventFields[5].Value is true);
        Check("alarm event (OfType where clause)", active != null && (ushort)active.EventFields[3].Value == 600
            && events.All(e => (NodeId)e.EventFields[0].Value == ObjectTypeIds.ExclusiveLimitAlarmType),
            string.Join(" ; ", events.Select(e => string.Join("/", e.EventFields.Select(f => f.Value)))));
        if (active != null)
        {
            var conditionId = (NodeId)active.EventFields[4].Value;
            var ack = await s.CallAsync(null, new CallMethodRequestCollection { new CallMethodRequest { ObjectId = conditionId,
                MethodId = MethodIds.AcknowledgeableConditionType_Acknowledge,
                InputArguments = new VariantCollection { new Variant((byte[])active.EventFields[2].Value), new Variant(new LocalizedText("dotnet")) } } }, default);
            await Task.Delay(400);
            lock (events) Check("Acknowledge through Call", StatusCode.IsGood(ack.Results[0].StatusCode)
                && events.Any(e => e.EventFields[6].Value is true), ack.Results[0].StatusCode.ToString());
        }

        // Methods: GetMonitoredItems, then a bad argument.
        var outArgs = await s.CallAsync(ObjectIds.Server, MethodIds.Server_GetMonitoredItems, default, sub.Id);
        Check("Call GetMonitoredItems", outArgs.Count == 2 && ((uint[])outArgs[0]).Length == 2, string.Join(",", (uint[])outArgs[1]));
        var bad = await s.CallAsync(null, new CallMethodRequestCollection { new CallMethodRequest { ObjectId = ObjectIds.Server,
            MethodId = MethodIds.Server_GetMonitoredItems, InputArguments = new VariantCollection { new Variant("x") } } }, default);
        Check("Call with a wrong argument type", bad.Results[0].StatusCode == StatusCodes.BadInvalidArgument
            && bad.Results[0].InputArgumentResults.FirstOrDefault() == StatusCodes.BadTypeMismatch, bad.Results[0].StatusCode.ToString());

        // TransferSubscriptions to a second session of the same user.
        using var s2 = await Connect(Url, SecurityPolicies.Basic256Sha256, MessageSecurityMode.SignAndEncrypt, User("operator", "s3cret"));
        var t = await s2.TransferSubscriptionsAsync(new SubscriptionCollection { sub }, true, default);
        Check("TransferSubscriptions", t);
        lock (values) values.Clear();
        await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = Id(1u), AttributeId = Attributes.Value, Value = new DataValue(new Variant(77)) } }, default);
        await Task.Delay(400);
        lock (values) Check("notifications after transfer", values.Contains(77), string.Join(",", values));
        await sub.DeleteAsync(true);
        await s2.CloseAsync();
    }

    static async Task History(Session s)
    {
        var start = DateTime.UtcNow.AddMinutes(-10);
        foreach (var v in new[] { 1.0, 2.0, 3.0 })
        {
            await s.WriteAsync(null, new WriteValueCollection { new WriteValue { NodeId = Id("Level"), AttributeId = Attributes.Value, Value = new DataValue(new Variant(v)) } }, default);
            await Task.Delay(5);
        }
        var end = DateTime.UtcNow.AddSeconds(1);
        async Task<HistoryReadResult> Read(HistoryReadDetails details, NodeId node, byte[] cp = null)
        {
            var r = await s.HistoryReadAsync(null, new ExtensionObject(details), TimestampsToReturn.Both, false,
                new HistoryReadValueIdCollection { new HistoryReadValueId { NodeId = node, ContinuationPoint = cp } }, default);
            return r.Results[0];
        }
        var raw = await Read(new ReadRawModifiedDetails { IsReadModified = false, StartTime = start, EndTime = end, NumValuesPerNode = 0, ReturnBounds = false }, Id("Level"));
        var data = (raw.HistoryData.Body as HistoryData)?.DataValues;
        Check("HistoryRead raw", StatusCode.IsGood(raw.StatusCode) && data != null
            && data.TakeLast(3).Select(d => (double)d.Value).SequenceEqual(new[] { 1.0, 2.0, 3.0 }),
            $"{raw.StatusCode} {raw.HistoryData.Body?.GetType().Name} {raw.HistoryData.TypeId} " + string.Join(",", data?.Select(d => d.Value) ?? []));
        // Continuation points.
        var all = new List<double>();
        byte[] cp = null;
        int calls = 0;
        do
        {
            var page = await Read(new ReadRawModifiedDetails { IsReadModified = false, StartTime = start, EndTime = end, NumValuesPerNode = 2, ReturnBounds = false }, Id("Level"), cp);
            all.AddRange(((HistoryData)page.HistoryData.Body).DataValues.Select(d => (double)d.Value));
            cp = page.ContinuationPoint;
        } while (cp != null && cp.Length > 0 && ++calls < 50);
        Check("HistoryRead continuation points", all.SequenceEqual(data.Select(d => (double)d.Value)), $"{calls + 1} calls");

        var proc = await Read(new ReadProcessedDetails { StartTime = start, EndTime = end, ProcessingInterval = 0,
            AggregateType = new NodeIdCollection { ObjectIds.AggregateFunction_Count },
            AggregateConfiguration = new AggregateConfiguration { UseServerCapabilitiesDefaults = true } }, Id("Level"));
        var count = (proc.HistoryData.Body as HistoryData)?.DataValues.FirstOrDefault();
        Check("HistoryRead processed (Count)", count != null && Convert.ToInt32(count.Value) == data.Count, $"{count?.Value} vs {data.Count}");

        var at = await Read(new ReadAtTimeDetails { ReqTimes = new DateTimeCollection { data[^1].SourceTimestamp }, UseSimpleBounds = true }, Id("Level"));
        var atv = (at.HistoryData.Body as HistoryData)?.DataValues.FirstOrDefault();
        Check("HistoryRead at time", atv != null && (double)atv.Value == 3.0, atv?.ToString());

        // HistoryUpdate: insert a value in the past, then read it back.
        var past = data[0].SourceTimestamp.AddMilliseconds(-1);
        var upd = await s.HistoryUpdateAsync(null, new ExtensionObjectCollection { new ExtensionObject(new UpdateDataDetails {
            NodeId = Id("Level"), PerformInsertReplace = PerformUpdateType.Insert,
            UpdateValues = new DataValueCollection { new DataValue(new Variant(-1.0), StatusCodes.Good, past) } }) }, default);
        var after = await Read(new ReadRawModifiedDetails { IsReadModified = false, StartTime = past, EndTime = past.AddMilliseconds(1), NumValuesPerNode = 0, ReturnBounds = false }, Id("Level"));
        Check("HistoryUpdate insert", StatusCode.IsGood(upd.Results[0].StatusCode)
            && ((HistoryData)after.HistoryData.Body).DataValues.Any(d => (double)d.Value == -1.0), upd.Results[0].OperationResults.FirstOrDefault().ToString());

        // Event history of the Server object.
        var filter = new EventFilter();
        filter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.EventType);
        filter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.Time);
        filter.AddSelectClause(ObjectTypeIds.BaseEventType, BrowseNames.Message);
        var evs = await Read(new ReadEventDetails { StartTime = start, EndTime = end, NumValuesPerNode = 0, Filter = filter }, ObjectIds.Server);
        var list = (evs.HistoryData.Body as HistoryEvent)?.Events;
        Check("HistoryRead events", StatusCode.IsGood(evs.StatusCode) && list?.Count > 0, $"{evs.StatusCode}, {list?.Count} events");
    }
}
