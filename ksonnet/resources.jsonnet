
//
// Definition for Alert Handler loader
//

// Import KSonnet library.
local k = import "ksonnet.beta.2/k.libsonnet";

// Short-cuts to various objects in the KSonnet library.
local depl = k.extensions.v1beta1.deployment;
local container = depl.mixin.spec.template.spec.containersType;
local resources = container.resourcesType;
local env = container.envType;
local annotations = depl.mixin.spec.template.metadata.annotations;

local alertHandler(input, output) =
    local worker(config) = {

        name: "analytics-alert-handler",
        local version = import "version.jsonnet",
        images: ["gcr.io/trust-networks/analytics-alert-handler:" + version],

        input: input,
        output: output,

        // Environment variables
        envs:: [

            // Hostname of Cherami
            env.new("CHERAMI_FRONTEND_HOST", "cherami"),

            // Cassandra settings.
            env.new("CASSANDRA_KEYSPACE", "alerts"),
            env.new("CASSANDRA_HOST", "cassandra")

        ],

        // Container definition.
        containers:: [

            container.new(self.name, self.images[0]) +
                container.env(self.envs) +
                container.args(["/queue/" + input] +
                               std.map(function(x) "output:/queue/" + x,
                                       output)) +
		container.imagePullPolicy("Always") +
                container.mixin.resources.limits({
                    memory: "64M", cpu: "0.55"
                }) +
                container.mixin.resources.requests({
                    memory: "64M", cpu: "0.5"
                })

        ],

        // Deployment definition.  replicas is number of container replicas,
        // inp is the input queue name, out is an array of output queue names.
        deployments:: [
            depl.new(self.name,
                    config.workers.replicas.alert_handler.min,
                    self.containers,
                    {app: "analytics-alert-handler",
                     component: "analytics"}) +
                annotations({"prometheus.io/scrape": "true",
                    "prometheus.io/port": "8080"})
        ],

        resources: self.deployments

    };
    worker;

alertHandler
