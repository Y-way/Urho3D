//
// Copyright (c) 2014-2016 THUNDERBEAST GAMES LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#pragma once

#include "../Core/Object.h"
#include "../Container/List.h"

namespace Urho3D
{

class URHO3D_API MetricsSnapshot : public RefCounted
{
    friend class Metrics;

    URHO3D_REFCOUNTED(MetricsSnapshot)

public:

    MetricsSnapshot() = default;

    String PrintData(unsigned columns = 1, unsigned minCount = 0);

    void Clear();

    /// Register instance(s) of classname in metrics snapshot
    void RegisterInstance(const String& classname, InstantiationType instantiationType, int count = 1);

private:

    struct InstanceMetric
    {
        String classname;
        unsigned count{};
        unsigned nativeInstances{};
        unsigned jsInstances{};
        unsigned netInstances{};
    };

    struct NodeMetric
    {
        String name;
        unsigned count{};
    };

    struct ResourceMetric
    {
        String name;
        String group;
        unsigned memoryUsage{};
    };

    static bool CompareInstanceMetrics(const InstanceMetric& lhs, const InstanceMetric& rhs);

    // StringHash(classname) => InstanceMetrics
    HashMap<StringHash, InstanceMetric> instanceMetrics_;

    // StringHash(node name) => NodeMetrics
    HashMap<StringHash, NodeMetric> nodeMetrics_;

    // StringHash(resource name) => ResourceMetrics
    HashMap<StringHash, ResourceMetric> resourceMetrics_;

};

/// Metrics subsystem
class URHO3D_API Metrics : public Object
{
    friend class Application;

    URHO3D_OBJECT(Metrics, Object)

public:

    /// Construct.
    explicit Metrics(Context* context);
    /// Destruct.
    ~Metrics() override;

    /// Enable the Metrics subsystem and start capturing instance data, expensive on CPU and may cause stuttering while enabled
    bool Enable();

    /// Get whether the Metrics subsystem is enabled or not
    bool GetEnabled() const { return enabled_; }    

    // Captures a snapshot of metrics data
    void Capture(MetricsSnapshot* snapshot);

    /// Prints names of registered node instances output string
    String PrintNodeNames() const;

private:

    // A RefCountedInfo entry, necessary as we need to access instances in RefCounted constructor/destructor
    // and info is not available (pure call access violations on abstract virtual functions)
    struct RefCountedInfo
    {
        // pointer to corresponding RefCounted, null means a free entry
        RefCounted *refCounted;
        // the has of the typename
        StringHash typeID;
        // for some types, like ScriptComponent it is useful to override the name to the JSComponent/CSComponent
        StringHash typeNameOverride;
        // the instantiation type of the instance
        InstantiationType instantiationType;
    };

    void Disable();

    void CaptureInstances(MetricsSnapshot* snapshot);
    void ProcessInstances();

    static void OnRefCountedCreated(RefCounted* refCounted);
    static void OnRefCountedDeleted(RefCounted* refCounted);

    void AddRefCounted(RefCounted* refCounted);
    void RemoveRefCounted(RefCounted* refCounted);

    // static instance
    static Metrics* metrics_;

    static bool everEnabled_;

    bool enabled_{};

    // typeid -> information for individual RefCounted
    mutable HashMap<StringHash, PODVector<RefCountedInfo>> instances_;

    // instances added since last capture, see note on RefCountedInfo as to why necessary
    PODVector<RefCounted*> processInstances_;

    // Lookup from string hashes to avoid String thrashing in the metrics subsystem with large numbers of instances
    HashMap<StringHash, String> names_;

};


}
