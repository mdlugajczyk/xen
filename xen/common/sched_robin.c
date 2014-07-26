#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/errno.h>

static const s_time_t DEFAULT_TIMESLICE = MILLISECS(1);

struct robin_private {
    spinlock_t lock;
};

struct robin_vcpu_private {
    struct vcpu *vcpu;
    bool_t awake;
};

struct robin_cpu_private {
  struct robin_vcpu_private *vcpus[256];
  unsigned int current_vcpu;
  unsigned int last_vcpu;
  spinlock_t lock;
};

#define ROBIN_PRIV(_ops) \
    ((struct robin_private *)((_ops)->sched_data))

#define ROBIN_PCPU(_c) \
    ((struct robin_cpu_private *)per_cpu(schedule_data, _c).sched_priv)
  
#define ROBIN_VCPU_PRIV(vc) ((struct robin_vcpu_private *)((vc)->sched_priv))

static int
robin_init(struct scheduler *ops)
{
    struct robin_private *prv;
    prv = xzalloc(struct robin_private);
    if ( prv == NULL )
        return -ENOMEM;

    ops->sched_data = prv;
    spin_lock_init(&prv->lock);

    return 0;
}

static void
robin_remove_vcpu(const struct scheduler *ops, struct vcpu *v)
{
    unsigned int i;
    unsigned long flags;
    struct robin_cpu_private *cpu_priv = ROBIN_PCPU(v->processor);

    spin_lock_irqsave(&cpu_priv->lock, flags);
    
    for (i = 0; i < cpu_priv->last_vcpu; i++)
    {
        if ( cpu_priv->vcpus[i] && cpu_priv->vcpus[i]->vcpu == v )
        {
            cpu_priv->vcpus[i] = NULL;
            break;
        }
    }

    spin_unlock_irqrestore(&cpu_priv->lock, flags);
}

static struct task_slice
robin_do_schedule(const struct scheduler *ops, s_time_t now, 
          bool_t tasklet_work_scheduled)
{
    unsigned int i;
    const int cpu = smp_processor_id();
    struct robin_cpu_private *cpu_priv = ROBIN_PCPU(cpu);
    struct task_slice ret;
    struct robin_vcpu_private *next = NULL;
    unsigned long flags;
    struct vcpu *curr = per_cpu(schedule_data, cpu).curr;
    
    spin_lock_irqsave(&cpu_priv->lock, flags);
    ret.migrated = 0;
    ret.time = DEFAULT_TIMESLICE;
    ret.task = NULL;
    for (i = 0; i < cpu_priv->last_vcpu; i++)
    {
        next = cpu_priv->vcpus[cpu_priv->current_vcpu];
        cpu_priv->current_vcpu++;
        cpu_priv->current_vcpu = cpu_priv->current_vcpu % cpu_priv->last_vcpu;

        if ( next && vcpu_runnable(next->vcpu) && !next->vcpu->is_running && next->awake && next->vcpu->processor == cpu)
        {
            ret.task = next->vcpu;
            break;
        }
    }

    if (ret.task == NULL && vcpu_runnable(curr))
    {
	ret.task = curr;
    }
    
    if ( ret.task == NULL || tasklet_work_scheduled )
    {
	ret.task = idle_vcpu[cpu];
    }

    spin_unlock_irqrestore(&cpu_priv->lock, flags);

    return ret;
}

static void *
robin_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct robin_vcpu_private *ret;
    ret =  xzalloc(struct robin_vcpu_private);

    if ( ret == NULL )
        return ret;

    ret->awake = 0;
    ret->vcpu = vc;

    return ret;
}

static void
robin_free_vdata(const struct scheduler *ops, void *priv)
{
    xfree(priv);
}

static void *
robin_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct robin_cpu_private *pcpu = xzalloc(struct robin_cpu_private);
    
    if (pcpu == NULL)
      return pcpu;
    pcpu->current_vcpu = 0;
    pcpu->last_vcpu = 0;
    spin_lock_init(&pcpu->lock);

    return pcpu;
}

static void
robin_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    xfree(pcpu);
}

static void *
robin_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    return xzalloc(struct vcpu);
}

static void
robin_free_domdata(const struct scheduler *ops, void *data)
{
    xfree(data);
}

static void robin_wake(const struct scheduler *ops, struct vcpu *v)
{
    int vcpu_added = 0;
    unsigned long flags;
    unsigned int i;
    struct robin_cpu_private *cpu_priv = ROBIN_PCPU(v->processor);

    if ( is_idle_vcpu(v) )
    {
        return;
    }

    spin_lock_irqsave(&cpu_priv->lock, flags);
    ROBIN_VCPU_PRIV(v)->awake = 1;

    for (i = 0; i < cpu_priv->last_vcpu; i++)
	if ( cpu_priv->vcpus[i] == ROBIN_VCPU_PRIV(v))
	    vcpu_added = 1;

    if (vcpu_added == 0)
    {
	cpu_priv->vcpus[cpu_priv->last_vcpu] = ROBIN_VCPU_PRIV(v);
	cpu_priv->last_vcpu++;
    }

    spin_unlock_irqrestore(&cpu_priv->lock, flags);
    
    if (is_idle_vcpu(per_cpu(schedule_data, v->processor).curr))
    {
	cpu_raise_softirq(v->processor, SCHEDULE_SOFTIRQ);
    }
}

static void robin_sleep(const struct scheduler *ops, struct vcpu *v)
{
    ROBIN_VCPU_PRIV(v)->awake = 0;
}

static int
robin_pick_cpu(const struct scheduler *ops, struct vcpu *vc)
{
    cpumask_t online_affinity;
    cpumask_t *online;

    online = cpupool_scheduler_cpumask(vc->domain->cpupool);
    cpumask_and(&online_affinity, vc->cpu_affinity, online);
    return cpumask_cycle(vc->vcpu_id % cpumask_weight(&online_affinity) - 1,
                         &online_affinity);
}

const struct scheduler sched_robin_def = {
    .name = "Round Robin Scheduler",
    .opt_name = "robin",
    .sched_id = XEN_SCHEDULER_ROBIN,

    .alloc_vdata    = robin_alloc_vdata,
    .free_vdata     = robin_free_vdata,
    .alloc_pdata    = robin_alloc_pdata,
    .free_pdata    = robin_free_pdata,
    .alloc_domdata    = robin_alloc_domdata,
    .free_domdata    = robin_free_domdata,
    .remove_vcpu = robin_remove_vcpu,

    .init = robin_init,

    .wake = robin_wake,
    .sleep = robin_sleep,
    .pick_cpu       = robin_pick_cpu,
    .do_schedule = robin_do_schedule,
};
