#ifndef PLATFORM_MAX_RESOURCE
#define PLATFORM_MAX_RESOURCE 6
#endif

#ifndef platform_resource_start
#define platform_resource_start(dev, index) ((dev)->resource[(index)].start)
#endif

#ifndef platform_resource_end
#define platform_resource_end(dev, index) ((dev)->resource[(index)].end)
#endif

#ifndef platform_resource_flags
#define platform_resource_flags(dev, index) ((dev)->resource[(index)].flags)
#endif

#ifndef platform_resource_len
#define platform_resource_len(dev, index) \
    ((platform_resource_start((dev), (index)) == 0 && \
      platform_resource_end((dev), (index)) == 0) ? 0 : \
            \
      (platform_resource_end((dev), (index)) - \
       platform_resource_start((dev), (index)) +1))
#endif
