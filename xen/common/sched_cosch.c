#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/errno.h>

static const s_time_t DEFAULT_TIMESLICE = MILLISECS(5);

struct cosch_private {
    spinlock_t lock;
};

struct cosch_vcpu_private {
    struct vcpu *vcpu;
    bool_t awake;
};

static struct cosch_vcpu_private *vcpus[256];
static unsigned int current_vcpu = 0;
static unsigned int last_vcpu = 0;

#define COSCH_PRIV(_ops) \
    ((struct cosch_private *)((_ops)->sched_data))

#define COSCH_VCPU_PRIV(vc) ((struct cosch_vcpu_private *)((vc)->sched_priv))

static int
cosch_init(struct scheduler *ops)
{
    struct cosch_private *prv;
    MD_PRINT();
    prv = xzalloc(struct cosch_private);
    if ( prv == NULL )
        return -ENOMEM;

    ops->sched_data = prv;
    spin_lock_init(&prv->lock);
    MD_PRINT();
    return 0;
}

static void
cosch_insert_vcpu(const struct scheduler *ops, struct vcpu *v)
{
    unsigned long flags;
    struct cosch_private *prv = COSCH_PRIV(ops);
    MD_PRINT();

    if (is_idle_vcpu(v) )
    {
	return;
    }

    spin_lock_irqsave(&prv->lock, flags);
    
    vcpus[last_vcpu] = COSCH_VCPU_PRIV(v);
    last_vcpu++;

    spin_unlock_irqrestore(&prv->lock, flags);
}

static void
cosch_remove_vcpu(const struct scheduler *ops, struct vcpu *v)
{
    unsigned int i;
    unsigned long flags;
    struct cosch_private *prv = COSCH_PRIV(ops);
    MD_PRINT();

    spin_lock_irqsave(&prv->lock, flags);
    
    for (i = 0; i < last_vcpu; i++)
    {
        if ( vcpus[i] && vcpus[i]->vcpu == v )
        {
            vcpus[i] = NULL;
            break;
        }
    }

     spin_unlock_irqrestore(&prv->lock, flags);
    MD_PRINT();
}

static struct task_slice
cosch_do_schedule(const struct scheduler *ops, s_time_t now, 
          bool_t tasklet_work_scheduled)
{
    unsigned int i;
    const int cpu = smp_processor_id();
    struct task_slice ret;
    struct cosch_vcpu_private *next = NULL;
    unsigned long flags;
    struct cosch_private *prv = COSCH_PRIV(ops);
    struct vcpu *curr = per_cpu(schedule_data, cpu).curr;
    MD_PRINT();

    spin_lock_irqsave(&prv->lock, flags);
    ret.migrated = 0;
    ret.time = DEFAULT_TIMESLICE;
    ret.task = NULL;
    for (i = 0; i < last_vcpu; i++)
    {
        next = vcpus[current_vcpu];
        current_vcpu++;
        current_vcpu = current_vcpu % last_vcpu;

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
        ret.time = SECONDS(1);
    }

    spin_unlock_irqrestore(&prv->lock, flags);
    printk("new vcpu: %d %d %d next index: %d state: %d for time: %ld\n", ret.task->vcpu_id, ret.task->processor,
           ret.task->domain->domain_id, current_vcpu, ret.task->runstate.state, ret.time);
    printk("Total number of vcpus: %d current_cpu: %d\n", last_vcpu,cpu);

    return ret;
}

static void *
cosched_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct cosch_vcpu_private *ret;
    MD_PRINT();
    ret =  xzalloc(struct cosch_vcpu_private);

    if ( ret == NULL )
        return ret;

    ret->awake = 0;
    ret->vcpu = vc;
    MD_PRINT();
    return ret;
}

static void
cosched_free_vdata(const struct scheduler *ops, void *priv)
{
    MD_PRINT();
    xfree(priv);
    MD_PRINT();
}

static void *
cosched_alloc_pdata(const struct scheduler *ops, int cpu)
{
    MD_PRINT();
    return xzalloc(struct vcpu);
}

static void
cosched_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    MD_PRINT();
    xfree(pcpu);
    MD_PRINT();
}

static void *
cosched_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    MD_PRINT();
    return xzalloc(struct vcpu);
}

static void
cosched_free_domdata(const struct scheduler *ops, void *data)
{
    MD_PRINT();
    xfree(data);
}

static void cosch_wake(const struct scheduler *ops, struct vcpu *v)
{
    MD_PRINT();

    if ( is_idle_vcpu(v) )
    {
        return;
    }
    COSCH_VCPU_PRIV(v)->awake = 1;
    if (is_idle_vcpu(per_cpu(schedule_data, v->processor).curr))
    {
	cpu_raise_softirq(v->processor, SCHEDULE_SOFTIRQ);
    }
}

static void cosch_sleep(const struct scheduler *ops, struct vcpu *v)
{
    MD_PRINT();
    COSCH_VCPU_PRIV(v)->awake = 0;
}

static int
cosched_pick_cpu(const struct scheduler *ops, struct vcpu *vc)
{
    cpumask_t online_affinity;
    cpumask_t *online;

    online = cpupool_scheduler_cpumask(vc->domain->cpupool);
    cpumask_and(&online_affinity, vc->cpu_affinity, online);
    return cpumask_cycle(vc->vcpu_id % cpumask_weight(&online_affinity) - 1,
                         &online_affinity);
}

const struct scheduler sched_cosch_def = {
    .name = "Coscheduling Scheduler",
    .opt_name = "cosch",
    .sched_id = XEN_SCHEDULER_COSCH,

    .alloc_vdata    = cosched_alloc_vdata,
    .free_vdata     = cosched_free_vdata,
    .alloc_pdata    = cosched_alloc_pdata,
    .free_pdata    = cosched_free_pdata,
    .alloc_domdata    = cosched_alloc_domdata,
    .free_domdata    = cosched_free_domdata,
    .insert_vcpu = cosch_insert_vcpu,
    .remove_vcpu = cosch_remove_vcpu,

    .init = cosch_init,

    .wake = cosch_wake,
    .sleep = cosch_sleep,
    .pick_cpu       = cosched_pick_cpu,
    .do_schedule = cosch_do_schedule,
};
