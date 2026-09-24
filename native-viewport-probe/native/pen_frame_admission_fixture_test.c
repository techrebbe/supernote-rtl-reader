#include "pen_frame_admission_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression)                                                       \
    do {                                                                        \
        if (!(expression)) {                                                     \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression);  \
            exit(1);                                                            \
        }                                                                       \
    } while (0)

static const struct pfa_scope canonical = {UINT64_C(77), 142, UINT64_C(9),
                                           UINT64_C(4)};
static const uint8_t aliases[3] = {0, 1, 2};
static unsigned assertions;

static uint8_t target(enum pfa_resource resource) {
    if (resource >= PFA_INK_PLANE_0 && resource <= PFA_INK_PLANE_2)
        return (uint8_t)(resource - PFA_INK_PLANE_0);
    if (resource >= PFA_PAINTER_ALIAS_0 && resource <= PFA_PAINTER_ALIAS_2)
        return aliases[resource - PFA_PAINTER_ALIAS_0];
    return PFA_NO_PLANE;
}

static struct pfa_receipt receipt(enum pfa_resource resource) {
    return (struct pfa_receipt){UINT64_C(1000) + (uint64_t)resource,
                                UINT64_C(200), target(resource)};
}

static void setup(struct pfa_frame *frame, struct pfa_observation *observed,
                  int omitted_resource) {
    memset(frame, 0, sizeof(*frame));
    memset(observed, 0, sizeof(*observed));
    observed->scope = canonical;
    CHECK(pfa_init(frame, canonical, aliases, 3));
    CHECK(pfa_exclude_input(frame, 100));
    observed->physical_input_excluded = 1;
    observed->active_mask |= PFA_BIT(PFA_PHYSICAL_INPUT);
    observed->route[PFA_PHYSICAL_INPUT] =
        (struct pfa_receipt){100, 0, PFA_NO_PLANE};
    CHECK(pfa_transition_endpoint(frame, 200, 1));
    observed->private_endpoint_active = 1;
    observed->active_mask |= PFA_BIT(PFA_PRIVATE_ENDPOINT);
    observed->route[PFA_PRIVATE_ENDPOINT] =
        (struct pfa_receipt){200, 0, PFA_NO_PLANE};
    for (int resource = PFA_INK_PLANE_0; resource < PFA_RESOURCE_COUNT;
         ++resource) {
        if (resource == omitted_resource) continue;
        struct pfa_receipt r = receipt((enum pfa_resource)resource);
        CHECK(pfa_bind(frame, (enum pfa_resource)resource, canonical, r));
        observed->route[resource] = r;
        observed->active_mask |= PFA_BIT(resource);
    }
}

static void active(struct pfa_frame *frame, struct pfa_observation *observed) {
    setup(frame, observed, -1);
    CHECK(pfa_construct(frame, observed));
    CHECK(frame->state == PFA_CONSTRUCTED);
}

static struct pfa_observation released(void) {
    struct pfa_observation after = {0};
    after.scope = canonical;
    return after;
}

static void happy_path(void) {
    struct pfa_frame frame;
    struct pfa_observation observed;
    active(&frame, &observed);
    CHECK(pfa_contact_begin(&frame, &observed, 51));
    CHECK(pfa_contact_sample(&frame, &observed, 51));
    CHECK(pfa_contact_end(&frame, &observed, 51));
    CHECK(pfa_contact_begin(&frame, &observed, 52));
    CHECK(pfa_contact_end(&frame, &observed, 52));
    CHECK(pfa_verify(&frame, &observed));
    {
        struct pfa_observation after = released();
        CHECK(pfa_teardown(&frame, &observed, &after,
                           frame.required_mask, 1));
    }
    CHECK(frame.state == PFA_CLOSED);
    CHECK(!pfa_verify(&frame, &observed));
    assertions++;
}

static void construction_requires_every_route(void) {
    for (int missing = PFA_INK_PLANE_0; missing < PFA_RESOURCE_COUNT;
         ++missing) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        setup(&frame, &observed, missing);
        CHECK(!pfa_construct(&frame, &observed));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
}

static void order_and_transition_are_strict(void) {
    struct pfa_frame frame;
    struct pfa_observation observed;
    memset(&frame, 0, sizeof(frame));
    CHECK(pfa_init(&frame, canonical, aliases, 3));
    CHECK(!pfa_transition_endpoint(&frame, 200, 1));
    CHECK(frame.state == PFA_QUARANTINED);
    memset(&frame, 0, sizeof(frame));
    CHECK(pfa_init(&frame, canonical, aliases, 3));
    CHECK(!pfa_bind(&frame, PFA_INK_PLANE_0, canonical,
                    receipt(PFA_INK_PLANE_0)));
    CHECK(frame.state == PFA_QUARANTINED);
    memset(&frame, 0, sizeof(frame));
    CHECK(pfa_init(&frame, canonical, aliases, 3));
    CHECK(pfa_exclude_input(&frame, 100));
    CHECK(!pfa_transition_endpoint(&frame, 200, 0));
    CHECK(frame.state == PFA_QUARANTINED);
    memset(&frame, 0, sizeof(frame));
    CHECK(pfa_init(&frame, canonical, aliases, 3));
    CHECK(pfa_exclude_input(&frame, 100));
    CHECK(!pfa_transition_endpoint(&frame, 100, 1));
    CHECK(frame.state == PFA_QUARANTINED);
    active(&frame, &observed);
    CHECK(!pfa_bind(&frame, PFA_INK_PLANE_0, canonical,
                    receipt(PFA_INK_PLANE_0)));
    CHECK(frame.state == PFA_QUARANTINED);
    assertions++;
}

static void partial_redirection_and_wrong_alias_fail(void) {
    for (int route = PFA_INK_PLANE_0; route < PFA_RESOURCE_COUNT; ++route) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        struct pfa_receipt redirected = receipt((enum pfa_resource)route);
        setup(&frame, &observed, route);
        redirected.private_endpoint = 999;
        CHECK(!pfa_bind(&frame, (enum pfa_resource)route, canonical,
                        redirected));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
    {
        struct pfa_frame frame;
        struct pfa_observation observed;
        struct pfa_receipt wrong = receipt(PFA_PAINTER_ALIAS_0);
        setup(&frame, &observed, PFA_PAINTER_ALIAS_0);
        wrong.target_plane = 2;
        CHECK(!pfa_bind(&frame, PFA_PAINTER_ALIAS_0, canonical, wrong));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
}

static void live_witness_must_match_before_construction(void) {
    for (int route = PFA_PHYSICAL_INPUT; route < PFA_RESOURCE_COUNT;
         ++route) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        setup(&frame, &observed, -1);
        observed.route[route].binding_token++;
        CHECK(!pfa_construct(&frame, &observed));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
    {
        struct pfa_frame frame;
        struct pfa_observation observed;
        setup(&frame, &observed, -1);
        observed.active_mask &= ~PFA_BIT(PFA_REFRESH);
        CHECK(!pfa_construct(&frame, &observed));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
}

static void late_substitution_never_admits_contact(void) {
    for (int route = PFA_PHYSICAL_INPUT; route < PFA_RESOURCE_COUNT;
         ++route) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        active(&frame, &observed);
        observed.route[route].binding_token++;
        CHECK(!pfa_contact_begin(&frame, &observed, 79));
        CHECK(frame.state == PFA_QUARANTINED);
        observed.route[route].binding_token--;
        CHECK(!pfa_verify(&frame, &observed));
        assertions++;
    }
}

static void painter_alias_substitution_never_admits_contact(void) {
    for (int change = 0; change < 2; ++change) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        active(&frame, &observed);
        if (change == 0)
            observed.route[PFA_PAINTER_ALIAS_1].target_plane = 2;
        else
            observed.route[PFA_PAINTER_ALIAS_1].private_endpoint = 999;
        CHECK(!pfa_contact_begin(&frame, &observed, 80));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
}

static void wrong_page_at_binding_fails(void) {
    struct pfa_frame frame;
    struct pfa_observation observed;
    struct pfa_scope another_page = canonical;
    setup(&frame, &observed, PFA_INK_PLANE_0);
    another_page.source_page_index++;
    CHECK(!pfa_bind(&frame, PFA_INK_PLANE_0, another_page,
                    receipt(PFA_INK_PLANE_0)));
    CHECK(frame.state == PFA_QUARANTINED);
    assertions++;
}

static void invalid_reinitialization_cannot_preserve_writer(void) {
    struct pfa_frame frame;
    struct pfa_observation observed;
    uint8_t bad_alias[] = {3};
    active(&frame, &observed);
    CHECK(!pfa_init(&frame, canonical, aliases, 3));
    CHECK(frame.state == PFA_QUARANTINED);
    active(&frame, &observed);
    CHECK(!pfa_init(&frame, canonical, bad_alias, 1));
    CHECK(frame.state == PFA_QUARANTINED);
    CHECK(!pfa_contact_begin(&frame, &observed, 1));
    assertions++;
}

static void only_declared_aliases_are_required(void) {
    struct pfa_frame frame;
    struct pfa_observation observed;
    uint8_t one_alias[] = {2};
    memset(&frame, 0, sizeof(frame));
    CHECK(pfa_init(&frame, canonical, one_alias, 1));
    memset(&observed, 0, sizeof(observed));
    observed.scope = canonical;
    CHECK(pfa_exclude_input(&frame, 100));
    observed.physical_input_excluded = 1;
    observed.active_mask |= PFA_BIT(PFA_PHYSICAL_INPUT);
    observed.route[PFA_PHYSICAL_INPUT] =
        (struct pfa_receipt){100, 0, PFA_NO_PLANE};
    CHECK(pfa_transition_endpoint(&frame, 200, 1));
    observed.private_endpoint_active = 1;
    observed.active_mask |= PFA_BIT(PFA_PRIVATE_ENDPOINT);
    observed.route[PFA_PRIVATE_ENDPOINT] =
        (struct pfa_receipt){200, 0, PFA_NO_PLANE};
    for (int route = PFA_INK_PLANE_0; route < PFA_RESOURCE_COUNT; ++route) {
        struct pfa_receipt r = receipt((enum pfa_resource)route);
        if (route == PFA_PAINTER_ALIAS_1 || route == PFA_PAINTER_ALIAS_2)
            continue;
        if (route == PFA_PAINTER_ALIAS_0) r.target_plane = 2;
        CHECK(pfa_bind(&frame, (enum pfa_resource)route, canonical, r));
        observed.route[route] = r;
        observed.active_mask |= PFA_BIT(route);
    }
    CHECK(pfa_construct(&frame, &observed));
    assertions++;
    observed.active_mask |= PFA_BIT(PFA_PAINTER_ALIAS_1);
    CHECK(!pfa_contact_begin(&frame, &observed, 1));
    CHECK(frame.state == PFA_QUARANTINED);
    assertions++;
}

static void scope_and_route_changes_during_contact_fail(void) {
    for (int scenario = 0; scenario < 7; ++scenario) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        active(&frame, &observed);
        CHECK(pfa_contact_begin(&frame, &observed, 81));
        switch (scenario) {
            case 0: observed.scope.document_id++; break;
            case 1: observed.scope.source_page_index++; break;
            case 2: observed.scope.page_generation++; break;
            case 3: observed.scope.rotation_epoch++; break;
            case 4: observed.physical_input_excluded = 0; break;
            case 5: observed.private_endpoint_active = 0; break;
            case 6: observed.route[PFA_JAVA_BINDER].binding_token++; break;
            default: exit(1);
        }
        CHECK(!pfa_contact_sample(&frame, &observed, 81));
        CHECK(frame.state == PFA_QUARANTINED);
        CHECK(!pfa_contact_end(&frame, &observed, 81));
        assertions++;
    }
}

static void stale_at_contact_start_and_wrong_contact_fail(void) {
    struct pfa_frame frame;
    struct pfa_observation observed;
    active(&frame, &observed);
    observed.scope.rotation_epoch++;
    CHECK(!pfa_contact_begin(&frame, &observed, 90));
    CHECK(frame.state == PFA_QUARANTINED);
    active(&frame, &observed);
    CHECK(pfa_contact_begin(&frame, &observed, 90));
    CHECK(!pfa_contact_sample(&frame, &observed, 91));
    CHECK(frame.state == PFA_QUARANTINED);
    assertions++;
}

static void no_incomplete_teardown(void) {
    for (int route = PFA_PHYSICAL_INPUT; route < PFA_RESOURCE_COUNT;
         ++route) {
        struct pfa_frame frame;
        struct pfa_observation observed;
        struct pfa_observation after = released();
        active(&frame, &observed);
        CHECK(!pfa_teardown(&frame, &observed, &after,
                            frame.required_mask & ~PFA_BIT(route), 1));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
    {
        struct pfa_frame frame;
        struct pfa_observation observed;
        struct pfa_observation after = released();
        active(&frame, &observed);
        CHECK(!pfa_teardown(&frame, &observed, &after,
                            frame.required_mask, 0));
        CHECK(frame.state == PFA_QUARANTINED);
        active(&frame, &observed);
        CHECK(pfa_contact_begin(&frame, &observed, 1));
        CHECK(!pfa_teardown(&frame, &observed, &after,
                            frame.required_mask, 1));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
    {
        struct pfa_frame frame;
        struct pfa_observation observed;
        struct pfa_observation after = released();
        active(&frame, &observed);
        after.route[PFA_PAINTER_ALIAS_1] = observed.route[PFA_PAINTER_ALIAS_1];
        CHECK(after.active_mask == 0);
        CHECK(!pfa_teardown(&frame, &observed, &after,
                            frame.required_mask, 1));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
    {
        struct pfa_frame frame;
        struct pfa_observation observed;
        struct pfa_observation after = released();
        active(&frame, &observed);
        after.active_mask = PFA_BIT(PFA_INK_PLANE_2);
        after.route[PFA_INK_PLANE_2] = observed.route[PFA_INK_PLANE_2];
        CHECK(!pfa_teardown(&frame, &observed, &after,
                            frame.required_mask, 1));
        CHECK(frame.state == PFA_QUARANTINED);
        assertions++;
    }
}

int main(void) {
    happy_path();
    construction_requires_every_route();
    order_and_transition_are_strict();
    partial_redirection_and_wrong_alias_fail();
    live_witness_must_match_before_construction();
    late_substitution_never_admits_contact();
    painter_alias_substitution_never_admits_contact();
    wrong_page_at_binding_fails();
    invalid_reinitialization_cannot_preserve_writer();
    only_declared_aliases_are_required();
    scope_and_route_changes_during_contact_fail();
    stale_at_contact_start_and_wrong_contact_fail();
    no_incomplete_teardown();
    printf("pen-frame host admission fixture: %u scenario checks passed\n",
           assertions);
    return 0;
}
